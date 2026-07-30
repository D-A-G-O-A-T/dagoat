import { useEffect, useRef } from "react";

/**
 * Stream C T5 hazard: long-running poll ticks must not setState after unmount.
 * @returns {import('react').MutableRefObject<boolean>} `.current === true` while mounted
 */
export function useMountedRef() {
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  return mounted;
}
