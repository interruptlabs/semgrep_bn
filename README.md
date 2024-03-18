# `semgrep_bn`

`semgrep_bn` is a Binary Ninja plugin designed to automate the process of generating pseudo-C code from binary files, running Semgrep over this pseudo-C, and presenting the results - all without having to leave the Binary Ninja environment.

![Semgrep Demo GIF](gifs/semgrep_bn_short_demo.gif)


## Installation

1. Clone the `semgrep_bn` repo (with its submodules) into the Binary Ninja plugins directory (see [here](https://docs.binary.ninja/guide/plugins.html) for the location of your plugin folder).

```shell
git clone --recurse-submodules https://github.com/interruptlabs/semgrep_bn
```

2. Install the Python dependencies.

```shell
pip install -r semgrep_bn/requirements.txt
```

3. Follow the installation instructions [here](https://semgrep.dev/docs/getting-started/) to install Semgrep.

## Usage

1. Open a binary file with Binary Ninja.
2. Navigate to the `Plugins` menu and select `Semgrep analysis`.
3. Select your Semgrep ruleset.
   To write your own semgrep rules, follow the instructions found [here](https://semgrep.dev/docs/writing-rules/rule-ideas/)!
   Some examples of rules are available [here](https://github.com/semgrep/semgrep-rules/tree/develop/c/lang/security) and [here](https://github.com/0xdea/semgrep-rules).
4. The plugin will analyse the binary, run Semgrep, and display the findings in an HTML report.

## Contributing

Contributions to `semgrep_bn` are welcome.
Please feel free to submit issues, fork the repository, and send pull requests!
