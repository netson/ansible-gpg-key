#!/usr/bin/python

# Copyright: (c) 2019, Rinck H. Sonnenberg - Netson <r.sonnenberg@netson.nl>
# License: MIT

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: gpg_key
short_description: Module to install and trust GPG keys
version_added: "2.7"
description: |
    Module to install and trust GPG keys from files and keyservers.
    I shouldn't have to tell you that it is a BAD idea to store your
    secret keys inside a playbook or role! Please take approriate measures
    to protect your sensitive information from falling into the wrong hands!
options:
    fpr:
        description: |
            Key Fingerprint to install from keyserver, to delete from target
            machine, or to get info on. To get info on all installed keys,
            use * as the value for fpr. Using any shorter ID than the full
            fingerprint will fail. Using the short ID's isn't recommended
            anyways, due to possible collisions.
        required: false
        type: str
    keyserver:
        description: Keyserver to download key from
        default: keyserver.ubuntu.com
        type: str
    file:
        description: |
            File on target machine containing the key(s) to install;
            be aware that a file can contain more than 1 key; if this
            is the case, all keys will be imported and all keys will
            receive the same trust level. The module auto-detects if
            the given key is a public or secret key.
        required: false
        type: path
    content:
        description: |
            Contents of keyfile to install on target machine
            just like the file, the contents can contain more than 1 key
            and all keys will receive the same trust level. The module
            auto-detects if the given key is a public or secret key.
            The content parameter simply creates a temporary file on the
            target host and then performs the same actions as the file
            parameter. It is just an easy method to not have to create
            a keyfile on the target machine first.
        required: false
        type: str
    manage_trust:
        description: |
            Setting controls wether or not the module controls the trust levels
            of the (imported) keys. If set to false, no changes will be made to
            the trust level regardless of the 'trust' setting.
        default: true
        type: bool
    trust:
        description: |
            Trust level to apply to newly imported keys or existing keys;
            please keep in mind that keys with a trust level other than 5
            need to be signed by a fully trusted key in order to effectively
            set the trust level. If your key is not signed by a fully trusted
            key and the trust level is 2, 3 or 4, the module will report a
            changed state on each run due to the fact that GnuPG will report
            an 'Unknown' trust level.
        choices:
        - 1
        - 2
        - 3
        - 4
        - 5
        default: 1
        type: str
    state:
        description: |
            Key should be present, absent, latest (keyserver only) or info.
            Info only shows info for key given via fpr. Alternatively, you
            can use the special value * for the fpr to get a list of all
            installed keys and their relevant info.
        default: present
        type: str
        choices:
        - present
        - absent
        - latest
        - info
    gpgbin:
        description: Full path to GnuPG binary on target host
        default: uses get_bin_path method to find gpg
        type: path
    homedir:
        description: |
            Full path to the gpg homedir you wish to use; If none is provided,
            gpg will use the default homedir of ~/.gnupg
            Please be aware that this will be the user executing the module
            on the target host! So there will likely be a difference between
            running the module with and without become:yes! If you don't want to
            be surprised, set the path to the homedir with the variable. For more
            information on the GnuPG homedir, check
            https://www.gnupg.org/gph/en/manual/r1616.html
        default: None
        type: path

author:
    - Rinck H. Sonnenberg (r.sonnenberg@netson.nl)
'''

EXAMPLES = '''
# install key from keyfile on target host and set trust level to 5
- name: add key(s) from file and set trust
  gpg_key:
    file: "/tmp/testkey.asc"
    trust: '5'

# make sure all keys in a file are NOT present on the keychain
- name: remove keys inside file from the keychain
  gpg_key:
    file: "/tmp/testkey.asc"
    state: absent

# install keys on the target host from a keyfile on the ansible master
- name: install keys on the target host from a keyfile on the ansible master
  gpg_key:
    content: "{{ lookup('file', '/my/tmp/file/on/host') }}"

# alternatively, you can simply provide the key contents directly
- name: install keys from key contents
    content: "-----BEGIN PGP PUBLIC KEY BLOCK-----........."

# install key from keyserver on target machine
- name: install key from default keyserver on target machine
  gpg_key:
    fpr: 0D69E11F12BDBA077B3726AB4E1F799AA4FF2279

# install key from keyserver on target machine and set trust level
- name: install key from alternate keyserver on target machine and set trust level 5
  gpg_key:
    fpr: 0D69E11F12BDBA077B3726AB4E1F799AA4FF2279
    keyserver: eu.pool.sks-keyservers.net
	trust: '5'

# delete a key from the target machine
- name: remove a key from the target machine
  gpg_key:
    fpr: 0D69E11F12BDBA077B3726AB4E1F799AA4FF2279
    state: absent

# get keyinfo for a specific key; will also return success if key not installed
- name: get keyinfo
  gpg_key:
    fpr: 0D69E11F12BDBA077B3726AB4E1F799AA4FF2279
    state: info

# get keyinfo for all installed keys, public and secret
- name: get keyinfo for all keys
  gpg_key:
    fpr: '*'
    state: info
'''

RETURN = '''
keys:
    description: |
        list of keys touched by the module;
        list contains dicts of fingerprint, keytype, capabilities and trust level for each key
        an exmaple output would looke like:
            A0880EC90DD07F5968CEE3B6C6B3D8E7A7CD2528:
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
        If you set the state to absent, and the key was already absent, obviously
        not all info will be available; it would look similar to:
            A0880EC90DD07F5968CEE3B6C6B3D8E7A7CD2528:
               changed: false
               fingerprint: A0880EC90DD07F5968CEE3B6C6B3D8E7A7CD2528
               state: absent
    type: list
    returned: always
debug:
    description: contains debug information
    type: list
    returned: when verbosity >= 2
'''

import re
import os
import time
from ansible.module_utils.basic import AnsibleModule
from packaging import version

# class to import GPG keys
class GpgKey(object):


    def __init__(self, module):
        """
        init method
        """
        # set ansible module
        self.module = module
        self.debugmsg = []
        self.installed_keys = {}
        self.changed = False

        # seed the result dict in the object
        # we primarily care about changed and state
        # change is if this module effectively modified the target
        # state will include any data that you want your module to pass back
        # for consumption, for example, in a subsequent task
        self.result = dict(
            changed=False,
            keys={},
            msg="",
        )

        # set gpg binary none was provided
        if not self.module.params["gpgbin"] or self.module.params["gpgbin"] is None:
            self.module.params["gpgbin"] = self.module.get_bin_path('gpg')


    def _vv(self, msg):
        """
        debug info
        """
        # add debug message
        self.debugmsg.append("{}".format(msg))


    def has_method(self, name):
        """
        method to check if other methods exist
        """
        return callable(getattr(self, name, None))


    def run(self):
        """
        run module with given parameters
        """
        # check versions of gnupg and libgcrypt
        # check homedir
        self.check_versions()
        self.check_homedir()

        # determine and run action
        if self.module.params["file"]:
            run_action = "file"
        elif self.module.params["fpr"]:
            run_action = "fpr"
        elif self.module.params["content"]:
            run_action = "content"
        else:
            self.module.fail_json(msg="You shouldn't be here; no valid action could be determined")

        # determine action and method
        run_state  = self.module.params["state"]
        run_method = "run_{}_{}".format(run_action, run_state)
        self._vv("determined action [{}] with state [{}]".format(run_action, run_state))

        # always check installed keys first
        self.check_installed_keys()
        #self.result["installed_keys"] = self.installed_keys

        # check if run method exists, and if not fail with an error
        if self.has_method(run_method):
            getattr(self, run_method)()
        else:
            self.module.fail_json(msg="Action [{}] is not supported with state [{}]".format(run_action, run_state))

        # check verbosity and add debug messages
        if self.module._verbosity >= 2:
            self.result['debug'] = "\n".join(self.debugmsg)

        # return result
        return self.result


    def run_file_present(self):
        """
        import key from file
        """
        # first, check if the file is OK
        keyinfo = self.check_file()

        self._vv("import new keys from file")

        # import count
        impcnt = 0
        trucnt = 0

        # then see if the key is already installed
        # fk = file key
        # ik = installed key
        for index, fk in enumerate(keyinfo["keys"]):

            # check expiration by checking trust
            if fk["trust_level"] in ['i','d','r','e']:
                self.module.fail_json(msg="key is either expired or invalid [trust={}] [expiration={}]".format(fk["trust_level"], fk["expirationdate"]))

            # check if key is installed
            installed = False
            for ik in self.installed_keys["keys"]:
                if (fk["fingerprint"] == ik["fingerprint"] and
                    fk["type"] == ik["type"] and
                    fk["key_capabilities"] == ik["key_capabilities"]
                   ):
                    self._vv("fingerprint [{}] already installed".format(fk["fingerprint"]))
                    keyinfo["keys"][index]["state"] = "present"
                    keyinfo["keys"][index]["changed"] = False
                    installed = True

                    # check trust
                    if not self.compare_trust(fk["trust_level"], self.module.params["trust"]):

                        # update trust level
                        self.set_trust(fk["fingerprint"], self.module.params["trust"])
                        trucnt += 1

                        # get trust level as displayed by gpg
                        tru_level, tru_desc = self.get_trust(self.module.params["trust"])
                        keyinfo["keys"][index]["changed"] = True
                        keyinfo["keys"][index]["trust_level"] = tru_level
                        keyinfo["keys"][index]["trust_level_desc"] = tru_desc                                       

                    continue

            if not installed:

                self._vv("fingerprint [{}] not yet installed".format(fk["fingerprint"]))

                # import file
                cmd = self.prepare_command("file", "present")

                # run subprocess
                rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)
                self._vv("fingerprint [{}] successfully imported".format(fk["fingerprint"]))
                keyinfo["keys"][index]["state"] = "present"
                keyinfo["keys"][index]["changed"] = True
                impcnt += 1

                # check trust
                if not self.compare_trust(fk["trust_level"], self.module.params["trust"]):

                    # update trust level
                    self.set_trust(fk["fingerprint"], self.module.params["trust"])
                    trucnt += 1

                    # get trust level as displayed by gpg
                    tru_level, tru_desc = self.get_trust(self.module.params["trust"])
                    keyinfo["keys"][index]["changed"] = True
                    keyinfo["keys"][index]["trust_level"] = tru_level
                    keyinfo["keys"][index]["trust_level_desc"] = tru_desc

        # set keyinfo
        self.set_keyinfo(keyinfo)

        # check import count
        if impcnt > 0 or trucnt > 0:
            self.result["changed"] = True

        # set message and return
        self.result["msg"] = "[{}] keys were imported; [{}] trust levels updated".format(impcnt, trucnt)
        return True


    def run_file_absent(self):
        """
        remove key(s) present in file
        """
        # first, check if the file is OK
        keyinfo = self.check_file()

        self._vv("remove keys identified in file")

        # key count
        keycnt = 0

        # then see if the key is installed or not
        # fk = file key
        # ik = installed key
        for index, fk in enumerate(keyinfo["keys"]):
            installed = False
            for ik in self.installed_keys["keys"]:
                if (fk["fingerprint"] == ik["fingerprint"] and
                    fk["type"] == ik["type"] and
                    fk["key_capabilities"] == ik["key_capabilities"]
                   ):
                    installed = True
                    continue

            if not installed:
                self._vv("fingerprint [{}] not installed; nothing to remove".format(fk["fingerprint"]))
                keyinfo["keys"][index]["state"] = "absent"
                keyinfo["keys"][index]["changed"] = False

            else:

                self._vv("fingerprint [{}] installed; will be removed".format(fk["fingerprint"]))

                # remove file
                cmd = self.prepare_command("file", "absent")

                # add fingerprint as argument
                cmd += [fk["fingerprint"]]

                # run subprocess
                rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)
                self._vv("fingerprint [{}] successfully removed".format(fk["fingerprint"]))
                keyinfo["keys"][index]["state"] = "absent"
                keyinfo["keys"][index]["changed"] = True
                keycnt += 1

                # re-run check installed command to prevent attempting to remove same
                # fingerprint again (for example after removing pub/sec counterpart
                # with the same fpr
                self.check_installed_keys()

        # set keyinfo
        self.set_keyinfo(keyinfo)

        # check import count
        if keycnt > 0:
            self.result["changed"] = True

        # return
        self.result["msg"] = "[{}] keys were removed".format(keycnt)
        return True


    def run_file_info(self):
        """
        method to only retrive current status of keys
        wether from file, content or fpr
        """
        # first, check if the file is OK
        keyinfo = self.check_file()

        self._vv("showing key info from file")

        # then see if the key is already installed
        # fk = file key
        # ik = installed key
        for index, fk in enumerate(keyinfo["keys"]):

            # check if key is installed
            installed = False
            for ik in self.installed_keys["keys"]:
                if (fk["fingerprint"] == ik["fingerprint"] and
                    fk["type"] == ik["type"] and
                    fk["key_capabilities"] == ik["key_capabilities"]
                   ):
                    self._vv("fingerprint [{}] installed".format(fk["fingerprint"]))
                    keyinfo["keys"][index]["state"] = "present"
                    keyinfo["keys"][index]["changed"] = False
                    installed = True
                    continue

            if not installed:
                # set state
                self._vv("fingerprint [{}] not installed".format(fk["fingerprint"]))
                keyinfo["keys"][index]["state"] = "absent"
                keyinfo["keys"][index]["changed"] = False

        # set keyinfo
        self.set_keyinfo(keyinfo)

        # set message and return
        return True


    def run_content_present(self):
        """
        import keys from content
        """
        # prepare content
        filename = self.prepare_content(self.module.params["content"])

        # set file parameter and run file present
        self.module.params["file"] = filename
        self.run_file_present()

        # delete content
        self.delete_content(filename)


    def run_content_absent(self):
        """
        remove keys from content
        """
        # prepare content
        filename = self.prepare_content(self.module.params["content"])

        # set file parameter and run file present
        self.module.params["file"] = filename
        self.run_file_absent()

        # delete content
        self.delete_content(filename)


    def run_content_info(self):
        """
        get key info from content
        """
        # prepare content
        filename = self.prepare_content(self.module.params["content"])

        # set file parameter and run file present
        self.module.params["file"] = filename
        self.run_file_info()

        # delete content
        self.delete_content(filename)


    def run_fpr_present(self):
        """
        import key from keyserver
        """
        self._vv("import new keys from keyserver")

        # set fpr shorthand
        fpr = self.module.params["fpr"]

        # set base values
        installed = False
        impcnt = 0
        trucnt = 0
        keyinfo = {
            'fprs': [],
            'keys': [],
        }

        # check if key is installed
        for ik in self.installed_keys["keys"]:

            if (fpr == ik["fingerprint"]):
                    
                # set keyinfo
                self._vv("fingerprint [{}] already installed".format(fpr))
                keyinfo["fprs"].append(fpr)
                keyinfo["keys"].append(ik)
                keyinfo["keys"][0]["state"] = "present"
                keyinfo["keys"][0]["changed"] = False
                installed = True

                # check trust
                if not self.compare_trust(ik["trust_level"], self.module.params["trust"]):

                    # update trust level
                    self.set_trust(fpr, self.module.params["trust"])
                    trucnt += 1

                    # get trust level as displayed by gpg
                    tru_level, tru_desc = self.get_trust(self.module.params["trust"])
                    keyinfo["keys"][0]["changed"] = True
                    keyinfo["keys"][0]["trust_level"] = tru_level
                    keyinfo["keys"][0]["trust_level_desc"] = tru_desc                                       

                continue

        if not installed:

            self._vv("fingerprint [{}] not yet installed".format(fpr))

            # import file
            cmd = self.prepare_command("fpr", "present")
            cmd += [fpr]

            # run subprocess
            rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)
            self._vv("fingerprint [{}] successfully imported from keyserver".format(fpr))

            # get info from specific key; keyservers only contain public keys
            # so no point in checking the secret keys
            cmd = self.prepare_command("check", "installed_public")
            cmd += [fpr]
            rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)
            keyinfo = self.process_colons(stdout)

            # check expiration by checking trust
            if keyinfo["keys"][0]["trust_level"] in ['i','d','r','e']:
                # deleted the expired key and fail
                cmd = self.prepare_command("fpr", "absent")
                cmd += [fpr]
                rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)
                self.module.fail_json(msg="key is either expired or invalid [trust={}] [expiration={}]".format(keyinfo["keys"][0]["trust_level"], keyinfo["keys"][0]["expirationdate"]))

            # update key info
            keyinfo["keys"][0]["state"] = "present"
            keyinfo["keys"][0]["changed"] = True
            impcnt += 1

            # check trust
            if not self.compare_trust(keyinfo["keys"][0]["trust_level"], self.module.params["trust"]):

                # update trust level
                self.set_trust(fpr, self.module.params["trust"])
                trucnt += 1

                # get trust level as displayed by gpg
                tru_level, tru_desc = self.get_trust(self.module.params["trust"])
                keyinfo["keys"][0]["changed"] = True
                keyinfo["keys"][0]["trust_level"] = tru_level
                keyinfo["keys"][0]["trust_level_desc"] = tru_desc

        # set keyinfo
        self.set_keyinfo(keyinfo)

        # check import count
        if impcnt > 0 or trucnt > 0:
            self.result["changed"] = True

        # set message and return
        self.result["msg"] = "[{}] keys were imported; [{}] trust levels updated".format(impcnt, trucnt)
        return True


    def run_fpr_absent(self):
        """
        remove key(s)
        """
        self._vv("delete keys based on fingerprint")

        # set fpr shorthand
        fpr = self.module.params["fpr"]

        # set base values
        installed = False
        keycnt = 0
        keyinfo = {
            'fprs': [],
            'keys': [],
        }

        # see if the key is installed or not
        # ik = installed key
        for ik in self.installed_keys["keys"]:
            if fpr == ik["fingerprint"]:
                if ("state" in ik and ik["state"] != "absent") or ("state" not in ik):
                    keyinfo["fprs"].append(fpr)
                    keyinfo["keys"].append(ik)
                    installed = True
                    continue

        if not installed:

            self._vv("fingerprint [{}] not installed; nothing to remove".format(fpr))
            key = {}
            key[fpr] = {
                "state"         : "absent",
                "changed"       : False,
                "fingerprint"   : fpr,
            }
            keyinfo["fprs"].append(fpr)
            keyinfo["keys"].append(key)

        else:

            self._vv("fingerprint [{}] installed; will be removed".format(fpr))

            # remove file
            cmd = self.prepare_command("fpr", "absent")

            # add fingerprint as argument
            cmd += [fpr]

            # run subprocess
            rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)
            self._vv("fingerprint [{}] successfully removed".format(fpr))
            keyinfo["keys"][0]["state"] = "absent"
            keyinfo["keys"][0]["changed"] = True
            keycnt += 1

        # re-run check installed command to prevent attempting to remove same
        # fingerprint again (for example after removing pub/sec counterpart
        # with the same fpr
        self.check_installed_keys()

        # set keyinfo
        self.set_keyinfo(keyinfo)

        # check import count
        if keycnt > 0:
            self.result["changed"] = True

        # return
        self.result["msg"] = "[{}] keys were removed".format(keycnt)
        return True


    def run_fpr_latest(self):
        """
        get the latest key from the keyserver
        """
        self._vv("get latest key from keyserver")

        # set fpr shorthand
        fpr = self.module.params["fpr"]

        # set base values
        installed = False
        updated = False
        updcnt = 0
        trucnt = 0
        keyinfo = {
            'fprs': [],
            'keys': [],
        }

        # check if key is installed
        for ik in self.installed_keys["keys"]:

            if (fpr == ik["fingerprint"]):
                    
                # set keyinfo
                self._vv("fingerprint [{}] installed; updating from server".format(fpr))
                keyinfo["fprs"].append(fpr)
                keyinfo["keys"].append(ik)
                keyinfo["keys"][0]["state"] = "present"
                keyinfo["keys"][0]["changed"] = False
                installed = True
                continue

        if not installed:

            self._vv("fingerprint [{}] not yet installed; install first".format(fpr))

            # import from keyserver
            self.run_fpr_present()
            return True

        else:

            self._vv("fetching updates from keyserver")

            # get updates from keyserver
            cmd = self.prepare_command("fpr", "latest")
            cmd += [fpr]
            rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)

            # see if any updates were downloaded or not
            # for some reason, gpg outputs these messages to stderr
            updated = re.search('gpg:\s+unchanged: 1\n', stderr) is None
            if updated:
                updcnt += 1

        # if key was updated, refresh info
        if updated:

            self._vv("key was updated on server")

            # get info from specific key; keyservers only contain public keys
            # so no point in checking the secret keys
            cmd = self.prepare_command("check", "installed_public")
            cmd += [fpr]
            rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)
            keyinfo = self.process_colons(stdout)

            # check expiration by checking trust
            if keyinfo["keys"][0]["trust_level"] in ['i','d','r','e']:
                # deleted the expired key and fail
                cmd = self.prepare_command("fpr", "absent")
                cmd += [fpr]
                rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)
                self.module.fail_json(msg="key is either expired or invalid [trust={}] [expiration={}]".format(keyinfo["keys"][0]["trust_level"], keyinfo["keys"][0]["expirationdate"]))

            # update key info
            keyinfo["keys"][0]["state"] = "present"
            keyinfo["keys"][0]["changed"] = True

            # check trust
            if not self.compare_trust(keyinfo["keys"][0]["trust_level"], self.module.params["trust"]):

                # update trust level
                self.set_trust(fpr, self.module.params["trust"])

                # get trust level as displayed by gpg
                tru_level, tru_desc = self.get_trust(self.module.params["trust"])
                keyinfo["keys"][0]["changed"] = True
                keyinfo["keys"][0]["trust_level"] = tru_level
                keyinfo["keys"][0]["trust_level_desc"] = tru_desc
                trucnt += 1

        # set keyinfo
        self.set_keyinfo(keyinfo)

        # check import count
        if updcnt > 0 or trucnt > 0:
            self.result["changed"] = True

        # set message and return
        self.result["msg"] = "[{}] keys were updated; [{}] trust levels updated".format(updcnt, trucnt)
        return True


    def run_fpr_info(self):
        """
        method to only return current key info
        will never report changed as it doesn't change anything on the target
        """
        # frp shorthand
        fpr = self.module.params["fpr"]
        keycount = 0

        # check if the request is for a single key or all
        if fpr == "*":
            keyinfo = self.installed_keys
            keycount = len(self.installed_keys["keys"])

        else:
            # then see if the key is already installed
            # ik = installed key
            installed = False
            keycount = 1
            keyinfo = {
                "fprs": [],
                "keys": [],
            }

            for ik in self.installed_keys["keys"]:
                if (fpr == ik["fingerprint"]):
                    self._vv("fingerprint [{}] installed".format(fpr))
                    keyinfo["fprs"].append(fpr)
                    keyinfo["fprs"].append(ik)
                    keyinfo["keys"][0]["state"] = "present"
                    keyinfo["keys"][0]["changed"] = False
                    installed = True
                    continue

            if not installed:
                # set state
                self._vv("fingerprint [{}] not installed".format(fpr))
                keyinfo["fprs"].append(fpr)
                keyinfo["keys"].append({})
                keyinfo["keys"][0]["fingerprint"] = fpr
                keyinfo["keys"][0]["state"] = "absent"
                keyinfo["keys"][0]["changed"] = False

        # set keyinfo
        self.set_keyinfo(keyinfo)
        self.result["msg"] = "listing info for [{}] key(s)".format(keycount)


    def prepare_content(self, content):
        """
        prepare content
        """
        # create temporary file and write contents
        filename = "tmp-gpg-{}.asc".format(time.time())
        self._vv("writing content to temporary file [{}]".format(filename))
        tmpfile = open("{}".format(filename),"w+")
        tmpfile.write(content)
        tmpfile.close()

        # return filename
        return filename


    def delete_content(self, filename):
        """
        delete temporary content
        """
        # cleanup
        self._vv("deleting temporary file [{}]".format(filename))
        os.remove(filename)


    def prepare_command(self, action, state):
        """
        prepare any gpg command
        """
        # set base command
        cmd = [self.module.params["gpgbin"]]

        # determine dry run / check mode
        if self.module.check_mode:
            cmd.append("--dry-run")

        # determine if homedir was set
        if self.module.params["homedir"]:
            cmd.append("--homedir")
            cmd.append(self.module.params["homedir"])

        # check versions
        if action == "check" and state == "versions":
            args = ["--version"]

        # check installed public keys
        if action == "check" and state == "installed_public":
            args = [
                "--with-colons",
                "--list-keys",
            ]

        # check installed secret keys
        if action == "check" and state == "installed_secret":
            args = [
                "--with-colons",
                "--list-secret-keys",
            ]

        # check file
        if action == "check" and state == "file":
            args = [
                "--with-colons",
                "--import-options",
                "show-only",
                "--import",
                self.module.params["file"],
            ]

        # file present
        if action == "file" and state == "present":
            args = [
                "--import",
                self.module.params["file"],
            ]

        # file absent
        if action == "file" and state == "absent":
            args = [
                "--batch",
                "--yes",
                "--delete-secret-and-public-key",
            ]

        # set ownertrust
        if action == "set" and state == "trust":
            args = ["--import-ownertrust"]

        # fpr present
        if action == "fpr" and state == "present":
            args = ["--recv-keys"]

            # determine if keyserver
            if self.module.params["keyserver"]:
                cmd.append("--keyserver")
                cmd.append(self.module.params["keyserver"])

        # fpr absent
        if action == "fpr" and state == "absent":
            args = [
                "--batch",
                "--yes",
                "--delete-secret-and-public-key",
            ]

        # fpr latest
        if action == "fpr" and state == "latest":
            args = ["--refresh-keys"]

            # determine if keyserver
            if self.module.params["keyserver"]:
                cmd.append("--keyserver")
                cmd.append(self.module.params["keyserver"])

        # merge cmd and args and return
        cmd += args
        self._vv("running command [{}]".format(" ".join(cmd)))
        return cmd


    def check_versions(self):
        """
        function to verify we have the right gnupg2 version
        """
        self._vv("checking gnupg and libgcrypt versions")

        # set command
        cmd = self.prepare_command("check", "versions")

        # run subprocess
        rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)

        # stdout lines - run_command returns a single string and we need the first and second line only
        lines = stdout.splitlines()

        # find gpg version
        regex_gpg = r"gpg\s+\(GnuPG[^)]*\)\s+(\d+\.\d+\.?\d*)$"
        match_gpg = re.search(regex_gpg, lines[0])

        # sanity check
        if match_gpg is None or match_gpg.group(1) is None:
            self.module.fail_json(msg="could not find a valid gpg version number in string [{}]".format(lines[0]))

        # find libgcrypt version
        regex_libgcrypt = r"libgcrypt\s+(\d+\.\d+\.?\d*)"
        match_libgcrypt = re.match(regex_libgcrypt, lines[1])

        # sanity check
        if match_libgcrypt is None or match_libgcrypt.group(1) is None:
            self.module.fail_json(msg="could not find a valid libgcrypt version number in string [{}]".format(lines[1]))

        # check versions
        versions        =  {'gpg'       : match_gpg.group(1),
                            'libgcrypt' : match_libgcrypt.group(1),
                           }
        req_gpg         = '2.1.17'
        req_libgcrypt   = '1.8.1'

        # display minimum versions
        self._vv("gpg_key module requires at least gnupg version [{}] and libgcrypt version [{}]".format(versions['gpg'], versions['libgcrypt']))

        # sanity check
        if version.parse(versions['gpg']) < version.parse(req_gpg) or version.parse(versions['libgcrypt']) < version.parse(req_libgcrypt):
            self.module.fail_json(msg="gpg version [{}] and libgcrypt version [{}] are required; [{}] and [{}] given".format(req_gpg, req_libgcrypt, versions['gpg'], versions['libgcrypt']))
        else:
            self._vv("gnupg version [{}] and libgcrypt version [{}] detected".format(versions['gpg'], versions['libgcrypt']))

        return True


    def check_installed_keys(self):
        """
        get list of keyfiles from current gpg homedir
        """
        self._vv("checking installed public keys on target host")

        # set command
        cmd = self.prepare_command("check", "installed_public")

        # run subprocess
        rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)

        # get public key info
        pubkeyinfo = self.process_colons(stdout)

        self._vv("found a total of [{}] public keys on target host".format(len(pubkeyinfo["fprs"])))

        self._vv("checking installed secret keys on target host")

        # set command
        cmd = self.prepare_command("check", "installed_secret")

        # run subprocess
        rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)

        # get public key info
        seckeyinfo = self.process_colons(stdout)

        self._vv("found a total of [{}] secret keys on target host".format(len(seckeyinfo["fprs"])))

        # merge keys
        keyinfo = {
            'fprs': pubkeyinfo["fprs"]+seckeyinfo["fprs"],
            'keys': pubkeyinfo["keys"]+seckeyinfo["keys"],
        }

        # remove any duplicate fingerprints which may occur in both pub and sec keys
        keyinfo["fprs"] = list(dict.fromkeys(keyinfo["fprs"]))

        # set keyinfo
        self.installed_keys = keyinfo


    def check_homedir(self):
        """
        check homedir
        """
        # check if homedir exists, if not, fail
        if self.module.params["homedir"] and not os.path.isdir(self.module.params["homedir"]):
            self.module.fail_json(msg="given homedir [{}] does not exist or not accessible by current ansible user".format(self.module.params["homedir"]))

        self._vv("homedir set to [{}]".format(self.module.params["homedir"]))

        return True


    def check_file(self):
        """
        check if param file exists on target machine
        check if file is a valid keyfile
        check for fingerprints
        """
        self._vv("checking keyfile on target host")

        # sanity check
        if not os.path.isfile(self.module.params["file"]):
            self.module.fail_json(msg="the keyfile [{}] does not exist on the target machine".format(self.module.params["file"]))
        else:
            self._vv("keyfile [{}] exists on target host".format(self.module.params["file"]))

        # get key info from file
        cmd = self.prepare_command("check", "file")

        # run subprocess
        rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)
        keyinfo = self.process_colons(stdout)

        return keyinfo


    def process_colons(self, cinfo):
        """
        fetch key information from colon output
        """
        #
        # SAMPLE DATA
        #
        # sec:u:256:22:41343326127FD34F:1566067845:::u:::cC:::+::ed25519:::0:
        # fpr:::::::::0D18E4B6B2698560729D00CE41343326127FD34F:
        # grp:::::::::54AA357FD85BA4D4B7CE86016A3734F00B1BDD07:
        # uid:u::::1566067845::00B9F0DC33EE293CC1E687FFA54A5EA805FD78F8::testing145 (TESTINGCOMM) <test@netson.nld>::::::::::0:
        #

        #
        # line types
        #
        # *** Field 1 - Type of record
        # 
        #     - pub :: Public key
        #     - crt :: X.509 certificate
        #     - crs :: X.509 certificate and private key available
        #     - sub :: Subkey (secondary key)
        #     - sec :: Secret key
        #     - ssb :: Secret subkey (secondary key)
        #     - uid :: User id
        #     - uat :: User attribute (same as user id except for field 10).
        #     - sig :: Signature
        #     - rev :: Revocation signature
        #     - rvs :: Revocation signature (standalone) [since 2.2.9]
        #     - fpr :: Fingerprint (fingerprint is in field 10)
        #     - pkd :: Public key data [*]
        #     - grp :: Keygrip
        #     - rvk :: Revocation key
        #     - tfs :: TOFU statistics [*]
        #     - tru :: Trust database information [*]
        #     - spk :: Signature subpacket [*]
        #     - cfg :: Configuration data [*]
        # 
        #     Records marked with an asterisk are described at [[*Special%20field%20formats][*Special fields]].
        #

        #
        # *** Field 12 - Key capabilities
        # 
        #     The defined capabilities are:
        # 
        #     - e :: Encrypt
        #     - s :: Sign
        #     - c :: Certify
        #     - a :: Authentication
        #     - ? :: Unknown capability
        # 
        #     A key may have any combination of them in any order.  In addition
        #     to these letters, the primary key has uppercase versions of the
        #     letters to denote the _usable_ capabilities of the entire key, and
        #     a potential letter 'D' to indicate a disabled key.
        #

        #
        # FIELD TYPES:
        #
        # - Field 1 - Type of record
        # - Field 2 - Validity
        # - Field 3 - Key length
        # - Field 4 - Public key algorithm
        # - Field 5 - KeyID
        # - Field 6 - Creation date
        # - Field 7 - Expiration date
        # - Field 8 - Certificate S/N, UID hash, trust signature info
        # - Field 9 -  Ownertrust
        # - Field 10 - User-ID
        # - Field 11 - Signature class
        # - Field 12 - Key capabilities
        # - Field 13 - Issuer certificate fingerprint or other info
        # - Field 14 - Flag field
        # - Field 15 - S/N of a token
        # - Field 16 - Hash algorithm
        # - Field 17 - Curve name
        # - Field 18 - Compliance flags
        # - Field 19 - Last update
        # - Field 20 - Origin
        # - Field 21 - Comment
        #

        # determine the correct line
        main_lines = ['sec','ssb','pub','sub']
        follow_lines = ['fpr','grp','uid']

        # indexes start at 0
        # main parts are for main_lines only
        mainparts = {
            'type'              : 0,
            'trust_level'       : 1,
            'key_length'        : 2,
            'pubkey_algorithm'  : 3,
            'keyid'             : 4,
            'creationdate'      : 5,
            'expirationdate'    : 6,
            'key_capabilities'  : 11,
            'hash_algorithm'    : 15,
            'curve_name'        : 16,
        }

        # indexes start at 0
        # follow parts for follow_lines only
        followparts = {
            'type'              : 0,
            'userid'            : 9, # this is the fingerprint for fpr records and the keygrip for grp records
        }

        #
        # 9.1.  Public-Key Algorithms
        # 
        #       ID           Algorithm
        #       --           ---------
        #       1          - RSA (Encrypt or Sign) [HAC]
        #       2          - RSA Encrypt-Only [HAC]
        #       3          - RSA Sign-Only [HAC]
        #       16         - Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
        #       17         - DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        #       18         - Reserved for Elliptic Curve
        #       19         - Reserved for ECDSA
        #       20         - Reserved (formerly Elgamal Encrypt or Sign)
        #       21         - Reserved for Diffie-Hellman (X9.42,
        #                    as defined for IETF-S/MIME)
        #       22         - Ed25519
        #       100 to 110 - Private/Experimental algorithm
        #
        pubkeys = {
            '1'                 : 'RSA (Encrypt or Sign)',
            '2'                 : 'RSA Encrypt-Only',
            '3'                 : 'RSA Sign-Only',
            '16'                : 'Elgamal (Encrypt-Only)',
            '17'                : 'DSA [FIPS186]',
            '18'                : 'Cv25519',
            '22'                : 'Ed25519',
        }

        #
        # 2. Field:  A letter describing the calculated trust. This is a single
	    # letter, but be prepared that additional information may follow
	    # in some future versions. (not used for secret keys)
        #
		# o = Unknown (this key is new to the system)
        # i = The key is invalid (e.g. due to a missing self-signature)
		# d = The key has been disabled
		# r = The key has been revoked
		# e = The key has expired
		# - = Unknown trust (i.e. no value assigned)
		# q = Undefined trust; '-' and 'q' may safely be treated as the same value for most purposes
		# n = Don't trust this key at all
		# m = There is marginal trust in this key
		# f = The key is full trusted.
		# u = The key is ultimately trusted; this is only used for
		#     keys for which the secret key is also available.
        #
        trustlevels = {
            'o'                 : 'Unknown/new',
            'i'                 : 'The key is invalid',
            'd'                 : 'The key has been disabled',
            'r'                 : 'The key has been revoked',
            'e'                 : 'The key has expired',
            '-'                 : 'Unknown trust',
            'q'                 : 'Undefined trust',
            'n'                 : 'Dont trust this key at all',
            'm'                 : 'There is marginal trust in this key',
            'f'                 : 'The key is fully trusted',
            'u'                 : 'The key is ultimately trusted',
        }

        # set list of keys and list of fingerprints
        keys = []
        fprs = []

        # set empty key dict
        curKey = {}

        # loop through lines
        for l in cinfo.splitlines():

            # split line into pieces
            pieces = l.split(":")

            # get current line type
            curType = pieces[mainparts.get('type')]

            # check for usage/capabilities
            if curType in main_lines:

                # check if curKey has values; if so add them to keys list first
                if "type" in curKey:
                    self._vv("found [{}] key with fingerprint [{}]".format(curKey["type"], curKey["fingerprint"]))
                    keys.append(curKey)

                # get pubkey algorithm
                p = pieces[mainparts.get('pubkey_algorithm')]
                z = pubkeys.get(p) if p is not None else ''

                # get trustlevel description
                p = pieces[mainparts.get('trust_level')]
                t = trustlevels.get(p) if p is not None else ''

                curKey = {
                    'type': pieces[mainparts.get('type')],
                    'trust_level': pieces[mainparts.get('trust_level')],
                    'trust_level_desc': t,
                    'key_length': pieces[mainparts.get('key_length')],
                    'pubkey_algorithm': z,
                    'keyid': pieces[mainparts.get('keyid')],
                    'creationdate': pieces[mainparts.get('creationdate')],
                    'expirationdate': pieces[mainparts.get('expirationdate')],
                    'key_capabilities': pieces[mainparts.get('key_capabilities')],
                    'hash_algorithm': pieces[mainparts.get('hash_algorithm')],
                    'curve_name': pieces[mainparts.get('curve_name')],
                }

            elif curType in follow_lines:

                # check follow line type
                if curType == "fpr":
                    curKey["fingerprint"] = pieces[followparts.get('userid')]
                    fprs.append(curKey["fingerprint"])
                elif curType == "grp":
                    curKey["keygrip"] = pieces[followparts.get('userid')]
                elif curType == "uid":
                    curKey["userid"] = pieces[followparts.get('userid')]

            # if we make it here we have encountered an unknown linetype
            # we should add the key info we have gathered so far to the keylist
            # and reset the key dict so it won't get added again in case more
            # keys will follow in the next lines
            else:
                if "type" in curKey:
                    self._vv("found [{}] key with fingerprint [{}]".format(curKey["type"], curKey["fingerprint"]))
                    keys.append(curKey)
                    curKey = {}

        # after the last line, see if any keys remain which need to be added
        if "type" in curKey:
            self._vv("found [{}] key with fingerprint [{}]".format(curKey["type"], curKey["fingerprint"]))
            keys.append(curKey)

        #
        # set and return results
        #
        return {
            'keys': keys,
            'fprs': fprs,
        }


    def compare_trust(self, trust1, trust2):
        """
        method to compare 2 trust levels
        """
        # check if we are managing trust
        if not self.module.params["manage_trust"]:
            self._vv("we're not managing trust")
            return True

        #
        # trust level returned by GnuPG
        # 'o' : 'Unknown/new',
        # 'i' : 'The key is invalid',
        # 'd' : 'The key has been disabled',
        # 'r' : 'The key has been revoked',
        # 'e' : 'The key has expired',
        # '-' : 'Unknown trust',
        # 'q' : 'Undefined trust',
        # 'n' : 'Dont trust this key at all',
        # 'm' : 'There is marginal trust in this key',
        # 'f' : 'The key is fully trusted',
        # 'u' : 'The key is ultimately trusted',
        #
        trust_map = {
            'o' : "0",
            'i' : "0",
            'd' : "0",
            'r' : "0",
            'e' : "0",
            '-' : "1",
            'q' : "1",
            'n' : "2",
            'm' : "3",
            'f' : "4",
            'u' : "5",
        }

        # convert trust if necessary
        if trust1 in trust_map.keys():
            trust1 = trust_map[trust1]
        if trust2 in trust_map.keys():
            trust2 = trust_map[trust2]

        self._vv("comparing trust [{}] and [{}]".format(trust1, trust2))

        # compare trust
        return trust1 == trust2


    def get_trust(self, trust):
        """
        method to get trust indicator from value
        """
        gpg_map = {
            '1' : '-',
            '2' : 'n',
            '3' : 'm',
            '4' : 'f',
            '5' : 'u',
        }

        trust_map = {
            '-' : 'Unknown trust',
            'n' : 'Dont trust this key at all',
            'm' : 'There is marginal trust in this key',
            'f' : 'The key is fully trusted',
            'u' : 'The key is ultimately trusted',
        }

        # return trust value
        return gpg_map[trust], trust_map[gpg_map[trust]]


    def set_trust(self, fingerprint, trust):
        """
        method to set ownertrust
        """
        #
        # Trust | Description               | Value ownertrust  | Value with colons
        # 1     | I don't know or won't say | 2                 | -|q|o
        # 2     | I do NOT trust            | 3                 | n
        # 3     | I trust marginally        | 4                 | m
        # 4     | I trust fully             | 5                 | f
        # 5     | I trust ultimately		| 6                 | u
        #

        self._vv("update trust level to [{}]".format(trust))

        # IMPORTANT: please keep in mind that with trust levels other than 5
        # the keys you import will need to be signed by a fully trusted key,
        # or be signed using the web of trust; see:
        # Using trust to validate keys: https://www.gnupg.org/gph/en/manual/x334.html
        # signing keys is not handled by this module and should be done by yourself
        # setting the trust.

        # trust map
        trust_map = {
            '1' : '2',
            '2' : '3',
            '3' : '4',
            '4' : '5',
            '5' : '6',
        }        

        # create temporary owner trust file
        # the newline at the end is required to prevent a 'gpg: line too long' error
        content = "{}:{}:\n".format(fingerprint, trust_map[trust])
        filename = self.prepare_content(content)

        # prepare command
        cmd = self.prepare_command("set", "trust")
        cmd += [filename]

        # run subprocess
        rc, stdout, stderr = self.module.run_command(args=cmd, check_rc=True)

        # delete content
        self.delete_content(filename)

        # return
        return True


    def set_keyinfo(self, keyinfo):
        """
        sets the keyinfo in an easy to process format
        starting with the fingerprint as the key,
        then the value is a dict with the key details
        """
        self._vv("setting key info to return to playbook")

        # loop through keyinfo and set fprs as dict key
        for key in keyinfo["keys"]:
            if "fingerprint" in key:
                self.result["keys"][key["fingerprint"]] = key


def main():

    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        fpr=dict(type='str', required=False),
        keyserver=dict(type='str', default='keyserver.ubuntu.com'),
        file=dict(type='path', required=False),
        content=dict(type='str', required=False),
        trust=dict(type='str', default='1', choices=['1','2','3','4','5']),
        manage_trust=dict(type='bool', default=True),
        state=dict(type='str', default='present', choices=['info', 'present', 'absent', 'latest']),
        gpgbin=dict(type='path', default=None),
        homedir=dict(type='path', default=None),
    )

    # set mutually exclusive params
    mutually_exclusive = [
        ['fpr', 'file', 'content'],
    ]

    # set at least one required field
    required_one_of = [
        ['fpr', 'file', 'content']
    ]

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        mutually_exclusive=mutually_exclusive,
        required_one_of=required_one_of,
        supports_check_mode=True
    )

    # run module
    gpgkey = GpgKey(module)
    result = gpgkey.run()

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # module.get_bin_path / def get_bin_path
    # module.run_command / def run_command
    
if __name__ == '__main__':
    main()
