"""Vendor-neutral webhook receiver that routes any HTTP POST through one of
the shipped atomic ingest skills and fans the OCSF output into the
configured sinks. See ../README.md for the design and deployment guide."""
