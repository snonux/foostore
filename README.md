# foostore

This is an humble Go tool for text and binary document encryption. It uses `AES-256-CBC` by default and the initialization vector is generated from an user input PIN.

This is for my own use. So the documentation here may be lacking. But feel free to try out yourself or ask!

## Features

* Works on MacOS, Linux and on Android via Termux.
* Encrypts and stores any type of documents and files (text, binary, etc). Meant for smaller files, such as text, PDFs, etc.
* All documents are stored in a Git repository.
* All file names are encrypted as well and kept in encrypted indices in the same Git repository.
* The indices are searchable through `fzf`, the fuzzy finder.
* The Git repository can be synchronized with N remote Git repositories (e.g. to two separate VMs for geo-redundancy).
* Text entries are edited using Helix  (or any other `$EDITOR`)
* Clipboard support for MacOS and GNOME (Linux).
* Interactive `geheim` shell support.
* Can import and export documuments in batches.
* Can shred exported data again.
