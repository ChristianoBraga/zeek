try:
    import shutil as sh
    import subprocess as sp
    import random as rand
except Exception as e:
    print(e)
    print('Check your Python 3 installation.')
    print('Either shutil, subprocess, or random is missing.')
    exit(1)

class LurkWrapperCmdException(Exception):
    pass

class LurkWrapperCommException(Exception):
    pass

class LurkWrapper:
    def __init__(self, timeout, cd, pd):
        lurk_path = sh.which('lurk')
        if lurk_path == None:
            raise LurkWrapperCmdException('Lurk is not installed.')
        self._timeout = timeout
        self._lurk_cmd = [lurk_path, f'--commits-dir={cd}', f"--proofs-dir={pd}"]

    def _mk_hide_cmd(salt, value):
        '''
        For the moment, only numbers, strings and code are allowed.
        '''
        assert(salt != None)
        assert(type(value) == list)
        if len(value) == 1 and value[0].isalpha():
            value = ['\"' + value[0] + '\"']
        cmd = 'Hide', ['!(hide', f'{salt}'] + value + [')']
        return cmd

    def _mk_load_and_hide_cmd(file, salt, fun):
        assert(file != None)
        assert(salt != None)
        assert(fun != None)
        return 'Load', ['!(load', f'\"{file}\")\n'] + ['!(hide', f'{salt}', f'{fun})']

    def _mk_open_cmd(value):
        assert(value != None)
        return 'Open', ['!(open', f'{value})']

    def _mk_apply_cmd(test, value):
        assert(test != None)
        assert(value != None)
        return 'Apply', ['!(fetch', f'{test})\n', '!(fetch', f'{value})\n', '((open', f'{test})', '(open', f'{value}))']

    def _mk_prove_cmd(test, value):
        apply_cmd = LurkWrapper._mk_apply_cmd(test, value)
        return 'Prove', apply_cmd[1] + ['\n!(prove)']

    def _mk_verify_cmd(proof_key):
        assert(proof_key != '' and proof_key != None)
        return 'Verify', ['!(verify', f'{proof_key})']

    def _mk_inspect_cmd(proof_key):
        assert(proof_key != '' and proof_key != None)
        return 'Verify', ['!(inspect', f'{proof_key})']
    
    def _has_error(out):
        assert(out != '' or out != None)
        return 'Error' in out or 'failed' in out
        
    def _get_error(out):
        assert(out != '' or out != None)
        if 'Error' in out:
            return out[out.find('Error:'):len(out)-1]
        elif 'failed' in out:
            return out[out.find('failed with ') + len('failed with '):out.find('\nExiting...')]
        else:
            return None
    
    def _get_hash(out):
        assert(not LurkWrapper._has_error(out))
        hash_idx = out.find('Hash: 0x') + len('Hash: 0x')
        exit_idx = out.find('\nExiting...')
        return out[hash_idx:exit_idx]

    def _get_output(out):
        assert(not LurkWrapper._has_error(out))
        res_idx = out.find('=> ')
        res_idx += len('=> ')
        exit_idx = out.find('\nExiting...')
        return out[res_idx:exit_idx]

    def _get_verify_output(out):
        assert(not LurkWrapper._has_error(out))
        res_idx = out.find('Proof ')
        exit_idx = out.find('\nExiting...')
        return out[res_idx:exit_idx]

    def _get_open_output(out):
        assert(not LurkWrapper._has_error(out))
        welcome_idx = out.find('you.\n') + len('you.\n') - 1
        exit_idx = out.find('\nExiting...')
        return out[welcome_idx+1:exit_idx].replace('FUNCTION', 'lambda').replace('.lurk.user.','')

    def _get_inspect_output(out):
        assert(not LurkWrapper._has_error(out))
        out_list = out.split()
        input_idx  = out_list.index('Input:')
        output_idx = out_list.index('Output:')
        iterations_idx = out_list.index('Iterations:')
        # It's assumed that the input is of the form
        # ((open <hash 1>)(open <hash 2>))
        # Therefore, <hash 1> is located at index 1 and <hash 2> is located at index 3.
        input_list = out_list[input_idx + 1:output_idx]
        input_hashes = input_list[1].strip(')'), input_list[3].strip(')')
        # Output value is a list
        output_value = out_list[output_idx + 1:iterations_idx] 
        return input_hashes, output_value
    
    def _get_proof_key(out):
        assert(not LurkWrapper._has_error(out))
        # Proof keys are surrouded by "" so we need to adjust the indices
        res_idx = out.find('Proof key: ') + len('Proof key: ') + 1 
        exit_idx = out.find('\nExiting...') - 1 
        return out[res_idx:exit_idx].strip('\"')
    
    def _run(self, cmd, cmd_list):
        try:
            echo_p = sp.Popen(["echo"] + cmd_list, stdout=sp.PIPE)
            lurk_p = sp.Popen(self._lurk_cmd, stdin=echo_p.stdout, stdout=sp.PIPE, stderr=sp.PIPE)
            echo_p.stdout.close()
            # Executes echo <cmd> | lurk
            # For example: echo !(hide 123 53) | lurk
            # comm_out = lurk_p.communicate(timeout=self._timeout)
            comm_out = lurk_p.communicate()
            if lurk_p.returncode < 0:
                raise LurkWrapperCommException(f'{cmd} failed.')
            else:
                return (comm_out[0]).decode('utf-8') + (comm_out[1]).decode('utf-8')
        except Exception as e:
            print(e)
            raise LurkWrapperCommException(f'{cmd} failed.')

    def load_and_hide(self, file, fun):
        salt = rand.randint(10_000_000_000, 100_000_000_000)
        try:            
            load_cmd = LurkWrapper._mk_load_and_hide_cmd(file, salt, fun)
            out = self._run(load_cmd[0], load_cmd[1])
            if LurkWrapper._has_error(out):
                return 1, LurkWrapper._get_error(out)
            else:
                return 0, LurkWrapper._get_hash(out)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Load failed.')

    def open(self, value):
        try:
            open_cmd = LurkWrapper._mk_open_cmd(value)
            out = self._run(open_cmd[0], open_cmd[1])
            if LurkWrapper._has_error(out):
                return 1, LurkWrapper._get_error(out)
            else:
                return 0, LurkWrapper._get_open_output(out)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Open failed.')

    def hide(self, value):
        salt = rand.randint(10_000_000_000, 100_000_000_000)
        try:
            hide_cmd = LurkWrapper._mk_hide_cmd(salt, value)
            out = self._run(hide_cmd[0], hide_cmd[1])
            if LurkWrapper._has_error(out):
                return 1, LurkWrapper._get_error(out)
            else:
                return 0, LurkWrapper._get_hash(out)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Hide failed.')

    def call(self, test, value):
        try:
            apply_cmd = LurkWrapper._mk_apply_cmd(test, value)
            out = self._run(apply_cmd[0], apply_cmd[1])
            if LurkWrapper._has_error(out):
                return 1, LurkWrapper._get_error(out)
            else:
                return 0, LurkWrapper._get_output(out)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Apply failed.')

    def prove(self, test, value):
        try:
            prove_cmd = LurkWrapper._mk_prove_cmd(test, value)
            out = self._run(prove_cmd[0], prove_cmd[1])
            if LurkWrapper._has_error(out):
                return 1, LurkWrapper._get_error(out)
            else:
                return 0, LurkWrapper._get_proof_key(out)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Prove failed.')

    def verify(self, proof_key):
        try:
            verify_cmd = LurkWrapper._mk_verify_cmd(proof_key)
            out = self._run(verify_cmd[0], verify_cmd[1])
            if LurkWrapper._has_error(out):
                return 1, LurkWrapper._get_error(out)
            else:
                return 0, LurkWrapper._get_verify_output(out)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Verify failed.')

    def inspect(self, proof_key, test, value, output):
        try:
            inspect_cmd = LurkWrapper._mk_inspect_cmd(proof_key)
            out = self._run(inspect_cmd[0], inspect_cmd[1])
            if LurkWrapper._has_error(out):
                return 1, LurkWrapper._get_error(out)
            else:
                # Proof_input is a pair of the hash representing a predicate and
                # the hash representing a value.
                # Proof output is list denoting a (structured) value.
                proof_input, proof_output = LurkWrapper._get_inspect_output(out)
                return 0, (test == proof_input[0] and value == proof_input[1] and output in proof_output)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Inspect failed.')
