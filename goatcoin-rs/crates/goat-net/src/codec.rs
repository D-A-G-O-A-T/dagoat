//! Compact wire codec for Task / TaskResult (device-agnostic). Used to serialize payloads
//! sealed over the PQ transport. TLV, big-endian, deterministic. Not a security boundary —
//! confidentiality/authenticity come from the AEAD channel; this is just framing.

use goat_protocol::types::{Task, TaskResult};

fn u32b(o: &mut Vec<u8>, n: u32) {
    o.extend_from_slice(&n.to_be_bytes());
}
fn u64b(o: &mut Vec<u8>, n: u64) {
    o.extend_from_slice(&n.to_be_bytes());
}
fn i64b(o: &mut Vec<u8>, n: i64) {
    o.extend_from_slice(&n.to_be_bytes());
}
fn blob(o: &mut Vec<u8>, b: &[u8]) {
    u32b(o, b.len() as u32);
    o.extend_from_slice(b);
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Reader<'a> {
    fn u32(&mut self) -> u32 {
        let v = u32::from_be_bytes(self.b[self.i..self.i + 4].try_into().unwrap());
        self.i += 4;
        v
    }
    fn u64(&mut self) -> u64 {
        let v = u64::from_be_bytes(self.b[self.i..self.i + 8].try_into().unwrap());
        self.i += 8;
        v
    }
    fn i64(&mut self) -> i64 {
        let v = i64::from_be_bytes(self.b[self.i..self.i + 8].try_into().unwrap());
        self.i += 8;
        v
    }
    fn blob(&mut self) -> Vec<u8> {
        let n = self.u32() as usize;
        let v = self.b[self.i..self.i + n].to_vec();
        self.i += n;
        v
    }
}

pub fn encode_task(t: &Task) -> Vec<u8> {
    let mut o = Vec::new();
    u32b(&mut o, t.task_class_id);
    blob(&mut o, t.engine_build_id.as_bytes());
    blob(&mut o, &t.payload);
    u64b(&mut o, t.seed);
    i64b(&mut o, (t.determinism_bound * 1000.0).round() as i64);
    o
}

pub fn decode_task(b: &[u8]) -> Task {
    let mut r = Reader { b, i: 0 };
    let task_class_id = r.u32();
    let engine_build_id = String::from_utf8(r.blob()).unwrap();
    let payload = r.blob();
    let seed = r.u64();
    let determinism_bound = r.i64() as f64 / 1000.0;
    Task {
        task_class_id,
        engine_build_id,
        payload,
        seed,
        determinism_bound,
    }
}

pub fn encode_result(t: &TaskResult) -> Vec<u8> {
    let mut o = Vec::new();
    u32b(&mut o, t.task_class_id);
    blob(&mut o, t.engine_build_id.as_bytes());
    u32b(&mut o, t.tokens.len() as u32);
    for &tok in &t.tokens {
        u32b(&mut o, tok);
    }
    u32b(&mut o, t.vector.len() as u32);
    for &v in &t.vector {
        i64b(&mut o, v);
    }
    o
}

pub fn decode_result(b: &[u8]) -> TaskResult {
    let mut r = Reader { b, i: 0 };
    let task_class_id = r.u32();
    let engine_build_id = String::from_utf8(r.blob()).unwrap();
    let nt = r.u32() as usize;
    let tokens = (0..nt).map(|_| r.u32()).collect();
    let nv = r.u32() as usize;
    let vector = (0..nv).map(|_| r.i64()).collect();
    TaskResult {
        task_class_id,
        tokens,
        vector,
        engine_build_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_roundtrip() {
        let t = Task {
            task_class_id: 10,
            engine_build_id: "b1".into(),
            payload: b"x".to_vec(),
            seed: 7,
            determinism_bound: 10.0,
        };
        let d = decode_task(&encode_task(&t));
        assert_eq!(
            (d.task_class_id, d.seed, d.determinism_bound),
            (10, 7, 10.0)
        );
    }

    #[test]
    fn result_roundtrip() {
        let r = TaskResult {
            task_class_id: 10,
            tokens: vec![1, 2, 3],
            vector: vec![-5, 6],
            engine_build_id: "b1".into(),
        };
        let d = decode_result(&encode_result(&r));
        assert_eq!(d.tokens, vec![1, 2, 3]);
        assert_eq!(d.vector, vec![-5, 6]);
    }
}
