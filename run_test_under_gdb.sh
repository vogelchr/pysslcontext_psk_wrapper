#!/bin/sh

exec gdb -ex "set args test_wrapper.py" -ex "run" python
