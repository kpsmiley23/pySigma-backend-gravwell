![Tests](https://github.com/SigmaHQ/pySigma-backend-Gravwell/actions/workflows/test.yml/badge.svg)
[Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/47c292239759399a6e3c73b0e9656b33/raw/SigmaHQ-pySigma-backend-Gravwell.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Gravwell Backend

This is the Gravwell backend for pySigma. It provides the package `sigma.backends.Gravwell` with the `GravwellBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.Gravwell`:

* Gravwell_windows_pipeline: Gravwell Windows log support
* Gravwell_windows_sysmon_acceleration_keywords: Adds fiels name keyword search terms to generated query to accelerate search.

It supports the following output formats:

* default: plain Gravwell queries
* savedsearches: Gravwell savedsearches.conf format.

This backend is currently maintained by:

* [Keith Smiley](https://github.com/kpsmiley23/)
