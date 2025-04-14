# PEDiff
Tool for comparing bytes and structural components of two PE files


## Installation

```bash
docker build . -t pediff
```

## Usage

Since the tool is run through docker, the `run_pediff.sh` script wraps the actual command simplicity:
```bash
./run_pediff.sh MODE [OPTIONS]
```

## Arguments

### Modes

This group defines if the PEDiff should compare a single pair of executables or all the possible pairs of executables contained in a folder.
They are mutually exclusive and at least one of them is required.

**Pair**

```
-f path/to/exe1 path/to/exe2
```

**Folder**

```
-d path/to/dir
```

### Options

**-p number_of_processes**: (valid only with -d) number of processes to use in Folder mode (default: 1)

**--print**: prints in stdout the results of the comparison.

In case of the option `--directory` is specified, the comparisons are aggregated as it follows:
- if the compared feature is a hash, it prints the percentage of matching comparisons;
- if it is TLSH, the failed comparisons are filtered out (i.e. comparisons with distance -1) and the mean value of the remaining ones is shown (in case all the comparisons failed, -1 is the assigned value)

**--main-only**: compare only the components (i.e. no additional features) using SHA256 and TLSH.

N.B: TLSH is not always able to compute the fingerprint for a given feature (usually due to very small sizes) and assigns as fingerprint `TNULL`.
A comparison between two features where at least one of them is TNULL results in an error and the distance -1 is assigned.
