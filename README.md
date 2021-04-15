# ansible-gpg-key
Module to manage GPG keys from files and keyservers.

## Introduction
Inspired by TNT (https://github.com/tnt/ansible-gpg-import-module), I created this module from scratch to better suit my needs. It allows you to manage GPG keys on a ansible managed target host. You can either provide keys (both public and secret) via keyfiles on the target or on the host or you can download keyfiles from keyservers. It also allows you to define a custom trust level for each key or retrieve info on installed keys.

### Ansible secrets lookup and generation module

Looking for an easy and secure way to generate and store GPG keys for your ansible hosts? Check out my secrets lookup module for ansible: https://github.com/netson/ahvl

## Requirements

This module was created for use with GnuPG **v2.2.4+** (including libgcrypt **v1.8.1+**), which is the default on Ubuntu 18.04 images. The libgcrypt version is also checked because I also use Ed25519 keys, which is supported only by newer versions of libgcrypt. The module may also work on older versions, but it is untested. Also, some commands have changed between GnuGP version 1.x and 2.x and therefore are incompatible.

To perform this version check, specify at least one of the options gpg_version or libgcrypt_version **and** make sure python package ```packaging``` is installed on the target host:
```bash
pip install packaging
```

## Installation

To install this module, clone it, download it, copy it, whatever (but name the file **gpg_key.py**), to a folder on your ansible host. Then, make sure ansible can find the module by pointing ```library``` to the folder containing the gpg_key.py file:

```
# set modules path, seperate with colons if multiple paths
library = /path/to/my/modules
```

## Options

Providing either **fpr**, **file** or **content** is required

| Option | Required | Type | Choices | Default | Description |
|--------|----------|------|---------|---------|-------------|
| **fpr** | ```False``` | ```str``` | | | Key Fingerprint to install from keyserver, to delete from target machine, or to get info on. To get info on all installed keys, use * as the value for fpr. Using any shorter ID than the full fingerprint will fail. Using the short ID's isn't recommended anyways, due to possible collisions. |
| **keyserver** | | ```str``` | | ```keyserver.ubuntu.com``` | Keyserver to download key from |
| **file** | ```False``` | ```path``` | | | File on target machine containing the key(s) to install; be aware that a file can contain more than 1 key; if this is the case, all keys will be imported and all keys will receive the same trust level. The module auto-detects if the given key is a public or secret key. |
| **content** | ```False``` | ```str``` | | | Contents of keyfile to install on target machine just like the file, the contents can contain more than 1 key and all keys will receive the same trust level. The module auto-detects if the given key is a public or secret key. The content parameter simply creates a temporary file on the target host and then performs the same actions as the file parameter. It is just an easy method to not have to create a keyfile on the target machine first. |
| **manage_trust** | | ```bool``` | | ```True``` | Setting controls wether or not the module controls the trust levels of the (imported) keys. If set to false, no changes will be made to the trust level regardless of the 'trust' setting. |
| **trust** | | ```str``` | ```[1-5]``` | ```1``` | Trust level to apply to newly imported keys or existing keys; please keep in mind that keys with a trust level other than 5 need to be signed by a fully trusted key in order to effectively set the trust level. If your key is not signed by a fully trusted key and the trust level is 2, 3 or 4, the module will report a changed state on each run due to the fact that GnuPG will report an 'Unknown' trust level. |
| **state** | | ```str``` | ```present```/ ```absent```/ ```latest```/ ```info``` | ```present``` | Key should be present, absent, latest (keyserver only) or info. Info only shows info for key given via fpr. Alternatively, you can use the special value * for the fpr to get a list of all installed keys and their relevant info. |
| **gpgbin** | | ```path``` | | ```get_bin_path``` method to find gpg | Full path to GnuPG binary on target host |
| **homedir** | | ```path``` | | ```None``` | Full path to the gpg homedir you wish to use; If none is provided, gpg will use the default homedir of ~/.gnupg Please be aware that this will be the user executing the module on the target host! So there will likely be a difference between running the module with and without become:yes! If you don't want to be surprised, set the path to the homedir with the variable. For more information on the GnuPG homedir, check https://www.gnupg.org/gph/en/manual/r1616.html |
| **gpg_version** | ```False``` | ```str``` | | | Minimal GnuPG version. Needs packaging module. |
| **libgcrypt_version** | ```False``` | ```str``` | | | Minimal libgcrypt version. Needs packaging module. |

## Examples

```YAML
# install key from keyfile on target host and set trust level to 5
- name: add key(s) from file and set trust
  gpg_key:
    file: "/tmp/testkey.asc"
    trust: '5'
```
```YAML
# make sure all keys in a file are NOT present on the keychain
- name: remove keys inside file from the keychain
  gpg_key:
    file: "/tmp/testkey.asc"
    state: absent
```
```YAML
# install keys on the target host from a keyfile on the ansible master
- name: install keys on the target host from a keyfile on the ansible master
  gpg_key:
    content: "{{ lookup('file', '/my/tmp/file/on/host') }}"
```
```YAML
# alternatively, you can simply provide the key contents directly
- name: install keys from key contents
    content: "-----BEGIN PGP PUBLIC KEY BLOCK-----........."
```
```YAML
# install key from keyserver on target machine
- name: install key from default keyserver on target machine
  gpg_key:
    fpr: 0D69E11F12BDBA077B3726AB4E1F799AA4FF2279
```
```YAML
# install key from keyserver on target machine and set trust level
- name: install key from alternate keyserver on target machine and set trust level 5
  gpg_key:
    fpr: 0D69E11F12BDBA077B3726AB4E1F799AA4FF2279
    keyserver: eu.pool.sks-keyservers.net
    trust: '5'
```
```YAML
# delete a key from the target machine
- name: remove a key from the target machine
  gpg_key:
    fpr: 0D69E11F12BDBA077B3726AB4E1F799AA4FF2279
    state: absent
```
```YAML
# get keyinfo for a specific key; will also return success if key not installed
- name: get keyinfo
  gpg_key:
    fpr: 0D69E11F12BDBA077B3726AB4E1F799AA4FF2279
    state: info
```
```YAML
# get keyinfo for all installed keys, public and secret
- name: get keyinfo for all keys
  gpg_key:
    fpr: '*'
    state: info
```

## Return values

The module returns a dictionary containing 3 main keys: ```fprs```, ```keys``` and ```msg```; a fourth key, ```debug```, is added when the verbosity level of your playbook run is at least 2 (-vv). It contains a bunch of debug statements informing you of the steps the module has taken.
```fprs``` is a list of unique fingerprints as touched by the module.
```keys``` contains a list of all keys touched by the module, including any info it could find.
```msg``` is simply a status message summarizing what the module has done.

### Sample output

```
{
    'fprs':
      - A0880EC90DD07F5968CEE3B6C6B3D8E7A7CD2528
    'keys':
      - A0880EC90DD07F5968CEE3B6C6B3D8E7A7CD2528:
          changed: false
          creationdate: '1576698396'
          curve_name: ed25519
          expirationdate: ''
          fingerprint: A0880EC90DD07F5968CEE3B6C6B3D8E7A7CD2528
          hash_algorithm: ''
          key_capabilities: cSC
          key_length: '256'
          keyid: C6B3D8E7A7CD2528
          pubkey_algorithm: Ed25519
          state: present
          trust_level: u
          trust_level_desc: The key is ultimately trusted
          type: pub
          userid: 'somekey <test@example.org>'
}
```

If you set the state to absent and the key was already absent, obviously not all info will be available; it would look similar to:
```
{
    'fprs':
      - A0880EC90DD07F5968CEE3B6C6B3D8E7A7CD2528
    'keys':
      - A0880EC90DD07F5968CEE3B6C6B3D8E7A7CD2528:
          changed: false
          fingerprint: A0880EC90DD07F5968CEE3B6C6B3D8E7A7CD2528
          state: absent
}
```

## License & Author

License: MIT
Written by: Rinck H. Sonnenberg <r.sonnenberg@netson.nl>
