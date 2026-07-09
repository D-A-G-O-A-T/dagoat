"""
DEVICE layer — backends live BELOW the GoatBackend trait and are device-specific
by nature. These are excluded from the neutrality source-scan (they are the thing
being abstracted, not protocol logic). They still must never inspect payload
content / model / license — only run opaque work.
"""
