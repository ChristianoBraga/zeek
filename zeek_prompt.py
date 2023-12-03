try:
    import os
    import json
    import prompt_toolkit as pt
    from prompt_toolkit.completion import NestedCompleter
    from lurk_wrapper import *
    from zeek_env import *
except Exception as e:
    print(e)
    print('Check your Python 3 installation.')
    print('Either os, json, prompt_toolkit, lurk_wrapper or zeek_env is missing.')
    exit(1) 

class ZeekPrompt:
    def __init__(self, path):
        self._zeek_env = ZeekEnv(path)
        # self.completer = pt.completion.WordCompleter(
            # ['call', 'check call', 'env', 'exit', 'hash hide', 'hash new party', 'help', 'hide', 'labels', 'new party', 
            #  'parties', 'party', 'hash prove', 'prove', 'save labels', 'send secret', 'send proof', 'verify'], ignore_case=True)
        self.session = pt.PromptSession(history=pt.history.FileHistory(self._zeek_env.get_hist()))
        labels_file_name = f'{path}/labels.json' 
        if os.path.exists(labels_file_name) and \
           os.path.getsize(labels_file_name) > 0:
            fh = open(labels_file_name, 'r')
            self._labels = json.load(fh)
            fh.close()
        else:
            self._labels = {}

    def save_labels(self):
        if self._labels != {}:
            labels_file_name = f'{self._zeek_env.get_path()}/labels.json'
            fh = open(labels_file_name, 'w')
            json.dump(self._labels, fh, indent=4)  
            fh.close()              


    def good_bye(self):
        print('\nBye')
        self.save_labels()

    def _right_prompt(self, party):
        if party != None and ZeekEnv.is_hash(party):
            if not self.empty_labels():
                k = [l for l, v in self._labels.items() if v == party]
                return f'<ansiyellow>{k[0]}</ansiyellow>:<ansigreen>{party[:4]}...{party[len(party) - 4:]}</ansigreen>'
            else:
                return f'<ansigreen>{party[:4]}...{party[len(party) - 4:]}</ansigreen>'
        elif party == 'public':
            return '<ansiyellow>public</ansiyellow>'
        else:
            return ''

    def prompt(self):
        style = pt.styles.Style.from_dict({
            # User input (default text).
            # '':              '#ff0066',
            # Prompt.
            'tool':          'ansigreen',
            'prompt_symbol': 'ansiyellow'
        })

        message = [
            ('class:tool',          'zeek '),
            ('class:prompt_symbol', '❯ '),
        ]

        '''
        A `NestedCompleter` is component of the `prompt_toolkit. An instance is a dictionary with the elements that should appear 
        when certain commands are typed in the REPL.
        - In the case of `call`, the secrets of the current party should appear twice. The second set of secrets
        is a nested dictionary which is a value for each secret in the first completion.
        - For `party`, the avaiable parties should be listed.
        - Command `prove` is completed with two secrets as in a `call`.
        - Command `send` can be completed as `secret` or `proof`. For the `secret` case, the secrets for the current party are 
        shown first and the parties next, after the `to` syntax. For the `proof` case, similarly to the `secret` case, the proofs 
        of the current party are shown, then the `to` syntax and then a list of the available parties.
        '''
        def _make_completer_dictionary(env, outter_list, inner_dict):
            d = {str(env.find_label_for_value(v)) 
                        if env.find_label_for_value(v) != None else v : inner_dict
                        for v in outter_list}
            sorted_keys = sorted(d, key=lambda x: (str(x)[0][0].isnumeric(), str(x)))
            d = {k : d[k] for k in sorted_keys}
            return d
        
        commits = self._zeek_env.get_commits_from_party()
        proofs  = self._zeek_env.get_proofs_from_party()
        parties = [p for p in self._zeek_env.get_parties() if p != self.get_party()]
        files = [f for f in os.listdir('.') if os.path.isfile(f)]
        completer = NestedCompleter.from_nested_dict({
            'call'  : _make_completer_dictionary(self, commits, _make_completer_dictionary(self, commits, None)), 
            'check' : {'call' : _make_completer_dictionary(self, self.get_labels(), 
                                 _make_completer_dictionary(self, self.get_labels(), 
                                    {'returns' : {'t'   : {'in' : _make_completer_dictionary(self, proofs, None)},
                                                  'nil' : {'in' : _make_completer_dictionary(self, proofs, None)}}}))},
            'secrets'   : None,
            'exit'  : None,
            'hash'  : {'hide': None,
                       'new party': None,
                       'prove': _make_completer_dictionary(self, commits, _make_completer_dictionary(self, commits, None))},
            'help'  : None,
            'hide'  : None,
            'labels': None,
            'new party': None,
            'parties': None,
            'party' : _make_completer_dictionary(self, parties, None),
            'prove' : _make_completer_dictionary(self, commits, _make_completer_dictionary(self, commits, {'as': None})), 
            'reveal': _make_completer_dictionary(self, commits, None),
            'save labels': None,
            'send'  : {'secret': _make_completer_dictionary(self, commits, {'to' : _make_completer_dictionary(self, parties, None)}), 
                       'proof':  _make_completer_dictionary(self, proofs,  {'to' : _make_completer_dictionary(self, parties, None)})},
            'verify': _make_completer_dictionary(self, proofs, None),
            'with' : _make_completer_dictionary(self, files, { 'hide': {'table': {'as': None},
                                                                        'function': None}})
        })

        return self.session.prompt(message, style=style, completer=completer, rprompt=pt.HTML(self._right_prompt(self._zeek_env.get_party())))

    def empty_labels(self):
        return self._labels == {}
    
    def get_labels(self):
        return self._labels.keys()
    
    def get_values(self):
        return self._labels.values()

    def get_items(self):
        return self._labels.items()
    
    def get_value(self, l):
        assert(self._labels != {} and l in self._labels.keys())
        return self._labels[l]

    def set_label(self, l, v):
        self._labels[l] = v 

    def find_label_for_value(self, value):
        key_list = [k for k in self._labels if self._labels[k] == value]
        if key_list != []:
            return key_list[0]
        return None

    def is_public(self):
        return self._zeek_env.get_party() == 'public'
        
    def get_party(self):
        return self._zeek_env.get_party()

    def handle_call(self, test, value):
        '''
        A call executes the application of test to value.
        Both commits should be desclosed to the current party, either
        because they were hidden by the current party itself or they were
        sent from another party to the current party.
        '''
        assert(type(value) != list)
        assert(self._zeek_env.get_party() != None)
        assert(ZeekEnv.is_hash(test) and ZeekEnv.is_hash(value))
        if not self._zeek_env.is_commited_by_current_party(test):
            return 1, f'Secret {test} was not hiden nor sent to {self._zeek_env.get_party()}.' 
        if not self._zeek_env.is_commited_by_current_party(value):
            return 1, f'Secret {value} was not hiden nor sent to {self._zeek_env.get_party()}.'             
        try:
            cd, pd = self._zeek_env.get_current_party_dirs()
            lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
            return lurkw.call('0x'+test, '0x'+value)
        except Exception as e:
            return 1, f'{e}\nUnexpected error while executing Call.'
        
    def handle_load_and_hide(self, file, fun):
        if not self.is_public():
            try:
                cd, pd = self._zeek_env.get_current_party_dirs()
                lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
                return lurkw.load_and_hide(file, fun)
            except Exception as e:
                return 1, f'{e}\nUnexpected error while executing load.'
        else:
            return 1, 'Only non-public parties may load values.'

    def handle_hide(self, value):
        assert(type(value) == list)
        if not self.is_public():
            try:
                cd, pd = self._zeek_env.get_current_party_dirs()
                lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
                return lurkw.hide(value)
            except Exception as e:
                return 1, f'{e}\nUnexpected error while executing hide.'
        else:
            return 1, 'Only non-public parties may hide values.'

    def handle_open(self, value):
        if not self.is_public():
            try:
                cd, pd = self._zeek_env.get_current_party_dirs()
                lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
                return lurkw.open(f'0x{value}')
            except Exception as e:
                return 1, f'{e}\nUnexpected error while executing open.'
        else:
            return 1, 'Only non-public parties may open values.'

    def handle_parties(self):
        if self.is_public():
            parties = self._zeek_env.get_parties()
            if parties != [] and parties != None:
                parties.sort()
                return 0, parties
            else:
                return 1, 'There are no parties'
        else:
            return 1, 'Only public can query parties.'

    def handle_party(self, party):
        current_party = self._zeek_env.get_party()  
        assert(current_party != None and (ZeekEnv.is_hash(current_party) or current_party == 'public') and (ZeekEnv.is_hash(party) or party == 'public'))
        if party == current_party:
            return 0, f'Party is already {current_party}.'
        else: 
            if self._zeek_env.set_party(party):
                return 0, f'Party set to {party}.'
            else:
                return 1, f'Party {party} does not exist.\nParty is still {current_party}.'

    def handle_new_party(self, value):
        assert(type(value) == list)
        try:
            cd, pd = self._zeek_env.get_current_party_dirs()
            lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
            rc, out = lurkw.hide(value)
            if rc == 0:
                self._zeek_env.add_party(out)            
            return rc, out
        except Exception as e:
            return 1, f'{e}\nUnexpected error while executing New party.'

    def handle_prove(self, test, value):
        try:
            cd, pd = self._zeek_env.get_current_party_dirs()
            lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
            return lurkw.prove('0x'+test, '0x'+value)
        except Exception as e:
            return 1, f'{e}\nUnexpected error while executing Prove.'

    def handle_verify(self, proof_key):
        try:
            cd, pd = self._zeek_env.get_current_party_dirs()
            lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
            return lurkw.verify(proof_key)
        except Exception as e:
            print(e)
            return 1, f'Unexpected error while executing Verify.'

    def handle_inspect(self, proof_key, test, value, output):
        try:
            cd, pd = self._zeek_env.get_current_party_dirs()
            lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
            return lurkw.inspect(f'\"{proof_key}\"', f'0x{test}', f'0x{value}', output)       
        except Exception as e:
            return 1, f'{e}\nUnexpected error while executing Inspect.'

    def handle_env(self):
        return self._zeek_env.get_commits_from_party(), self._zeek_env.get_proofs_from_party()
                
    def handle_send_commit(self, target_party, hash):
        if not self.is_public():
            if self._zeek_env.is_commited_by_current_party(hash): 
                return self._zeek_env.send_commit_from_current_party(target_party, hash)
            else:
                return 1, f'Secret {hash} was not commited by {self._zeek_env.get_party()}.'
        else:
            return 1, f'Public can not send secrets.'

    def handle_send_proof(self, target_party, proof):
        if not self.is_public():
            if self._zeek_env.is_proven_by_current_party(proof): 
                return self._zeek_env.send_proof_from_current_party(target_party, proof)
            else:
                return 1, f'Proof {proof} was not generated by {self._zeek_env.get_party()}.'
        else:
            return 1, f'Public can not send proofs.'
