<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Hamish Coleman
-->

# Linting

Checking all the lint rules can be done with `make lint`

- All python code is linted with `flake8`
- C code is linted using `uncrustify` with the specific config found in the
  `uncrustify.cfg` file

The C code is formatted as uncrustify 0.77.1 formats it.  Other versions
format a few constructs differently (0.72, which Ubuntu 22.04 packages,
indents the bodies of multi-line macros in another way), so the lint job in
CI builds 0.77.1 from source.  To get the same version locally:

```
git clone --depth 1 --branch uncrustify-0.77.1 https://github.com/uncrustify/uncrustify.git
cmake -S uncrustify -B uncrustify/build -DCMAKE_BUILD_TYPE=Release
make -C uncrustify/build
sudo cp uncrustify/build/uncrustify /usr/local/bin/
```

`scripts/indent.sh -i <file>` reformats a file in place.

A Markdown file carries its SPDX tags (licence and copyright) in an HTML
comment at its top, so that they stay in the source without showing on
the rendered page, on GitHub as in the docs built by MkDocs:

```
<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright ...
-->

# Title
```
