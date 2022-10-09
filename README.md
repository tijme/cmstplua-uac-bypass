<p align="center">
    <img src="https://raw.githubusercontent.com/tijme/uac-bypass-cmstplua/master/.github/logo.png" width="650"/>
</p>
<p align="center">
    <a href="https://github.com/tijme/uac-bypass-cmstplua/blob/master/LICENSE.md"><img src="https://raw.finnwea.com/shield/?firstText=Source&secondText=Licensed" /></a>
    <br/>
    <b>Cobalt Strike Beacon Object File for bypassing UAC via the CMSTPLUA COM interface.</b>
    <br/>
    <sup>Built by <a href="https://www.linkedin.com/in/tijme/">Tijme</a>. Credits to <a href="https://github.com/lldre">Alex</a> for teaching me! Made possible by <a href="https://northwave-security.com/">Northwave Security</a> <img src="https://raw.githubusercontent.com/tijme/uac-bypass-cmstplua/master/.github/northwave.png"/></sup>
    <br/>
</p>

## Description

This is a Cobalt Strike (CS) Beacon Object File (BOF) which exploits the CMSTPLUA COM interface. It masquerade the PEB of the current process to a Windows process, and then utilises COM Elevation Moniker on the CMSTPLUA COM object in order to execute commands in an elevated context.

<p align="center">
    <img src="https://raw.githubusercontent.com/tijme/uac-bypass-cmstplua/master/.github/output.png" />
</p>

## Usage

Clone this repository first. Then review the code, compile from source and use it in Cobalt Strike.

**Compiling**

	make

**Usage**

Load the `UACBypassCMSTPLUA.cna` script using the Cobalt Strike Script Manager. Then use the command below to execute the exploit.

    $ uac_bypass_cmstplua

## Limitations

* The BOF spawns a new process (in which UAC is bypassed).
* The BOF does not read the output of the spawned process.
* The UAC bypass is not allowed on the beacon itself.

## Issues

Issues or new features can be reported via the [issue tracker](https://github.com/tijme/uac-bypass-cmstplua/issues). Please make sure your issue or feature has not yet been reported by anyone else before submitting a new one.

## License

Copyright (c) 2022 Tijme Gommers & Northwave Security. All rights reserved. View [LICENSE.md](https://github.com/tijme/uac-bypass-cmstplua/blob/master/LICENSE.md) for the full license.
