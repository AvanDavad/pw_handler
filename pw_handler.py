from getpass import getpass
import random
import string
import re
import os
import sys
import argparse

parser = argparse.ArgumentParser(description='password handling.')
parser.add_argument('input_file', metavar='/path/to/input/file',
                    help='absolute path to input file')
args = parser.parse_args()

from Crypto.Cipher import AES

class PasswordHandler:
    def __init__(self, filename):
        self.filename = filename
        self._init_commands()
        self._get_password()
        self._load()
        self._start()
        
    def _init_commands(self):
        self.COMMANDS = [
            (self._quit, ['q', 'q!', 'wq', 'sq'], 'quit'),
            (self._read, ['r', 'read'], 'read content. e.g. `read 10 12`: read lines 10 and 11'),
            (self._write, ['w', 'write'], 'write new row'),
            (self._delete_all, ['D', 'DELETE'], 'delete all rows'),
            (self._delete_row, ['d', 'delete'], 'delete row. e.g. `d 0` to delete 0th row'),
            (self._find, ['f', 'find'], 'find rows by regexp, e.g. `f a.-?`'),
            (self._generate_password, ['gen', 'generate'], 'e.g.: `gen 12` will give 12 character long password'),
            (self._clear, ['c', 'clear'], 'clear the screen'),
            (self._save, ['s', 'save'], 'save the current contents'),
            (self._change_key, ['change'], 'change the password'),
            (self._help, ['h', 'help'], 'show this help message')
        ]
        
    def _get_password(self):
        x = getpass()
        x_list = x.split('.')
        x_list = (x_list*16)[:16]
        x_list = [int(c) for c in x_list]
        prekey = bytes(x_list)
        obj = AES.new(bytes([int(i%5==0) for i in range(16)]), 
                      AES.MODE_CBC, 
                      bytes([0 for _ in range(16)]))
        self.key = obj.encrypt(prekey)
        
    def _load(self):
        self._read_file()
        self.content = self._decrypt()
        self._refresh_content_lines()
    
    def _read_file(self):
        if not os.path.isfile(self.filename):
            print('no file {}. initializing new one'.format(self.filename))
            self.ciphertext = bytearray()
        else:
            with open(self.filename, 'rb') as f:
                self.ciphertext = bytearray(f.read())
    
    def _refresh_content_lines(self):
        self.content_lines = self.content.split(b'\n')
        self.content_lines = [line for line in self.content_lines if len(line) > 0]
    
    def _start(self):
        while True:
            inp = input('>')
            if inp == '':
                continue
            
            x0 = inp.split()[0]
            params = inp.split()[1:]
            for fun, command, _ in self.COMMANDS:
                if x0 in command:
                    fun(x0, params)
                    break
            else:
                print('invalid command: {}'.format(x0))
                print('enter h or help for list of commands!')
    
    def _help(self, x0=None, params=None):
        for _, command, help_msg in self.COMMANDS:
            print('{}: {}'.format(' or '.join(command), help_msg))
        
    def _delete_all(self, x0=None, params=None):
        x = input('delete all rows? (y/n)')
        if x=='y':
            print('deleted all rows.')
            self.content = b''
            self.content_lines = bytearray()
        elif x=='n':
            print('not deleting all rows.')
        else:
            print('enter either y or n.')
    
    def _delete_row(self, x0=None, params=None):
        row = self._get_first(params)
        row = self._validate_row(row)
        if row is None:
            return
        print('deleted:{}'.format(self.content_lines[row].decode()))
        self.content_lines = self.content_lines[:row] + self.content_lines[row+1:]
        self.content = b'\n'.join(self.content_lines)
    
    def _validate_row(self, row):
        try:
            r = int(row)
        except:
            print('please enter a valid integer!')
            return
        if (r<0) or (r>=len(self.content_lines)):
            print('please enter a valid row number!')
            return
        return r
    
    def _find(self, x0=None, params=None):
        regex = self._get_first(params)
        regex = re.compile(regex, re.IGNORECASE)
        for i, line in enumerate(self.content_lines):
            s = regex.search(line.decode())
            if s is not None:
                self._print_line(i)
    
    def _quit(self, x0, params=None):
        if x0 == 'q':
            save = input('save changes (y/n)?:')
            if save == 'y':
                return self._save_quit()
            if save=='n':
                return self._force_quit()
            else:
                print('please enter either y or n!')
                return False
        if x0 == 'q!':
            return self._force_quit()
        if x0 in ['wq', 'sq']:
            return self._save_quit()
    
    def _force_quit(self):
        print('not saving changes')
        sys.exit()
    
    def _save_quit(self):
        self._save()
        sys.exit()
    
    def _write(self, x0=None, params=None):
        msg = ' '.join(params)
        try:
            msg = bytearray(msg, encoding='ascii')
            if len(msg) > 0:
                self.content_lines.append(msg)
                self.content = b'\n'.join(self.content_lines)
        except:
            print('something went wrong.. please use only ascii!')
    
    def _read(self, x0=None, params=None):
        st_row = self._get_first(params)
        st_row = 0 if st_row=='' else int(st_row)
        end_row= self._get_second(params)
        end_row=len(self.content_lines) if end_row=='' else int(end_row) 
        for i, line in enumerate(self.content_lines):
            if (i>=st_row) and (i<end_row):
                self._print_line(i)
    
    def _print_line(self, i):
        print('{}:{}'.format(i, self.content_lines[i].decode()))
    
    def _generate_password(self, x0=None, params=None):
        k = self._get_first(params)
        k = int(k) if len(k)>0 else 8
        k = max(k,4)
        good_pwd = False
        while not good_pwd:
            good_pwd = True
            patterns = [string.digits,
                        string.ascii_lowercase,
                        string.ascii_uppercase,
                        string.punctuation]
            chars = ''.join(patterns)
            pwd = ''.join(random.choices(chars, k=k))
            for pattern in patterns:
                s = re.search('[{}]'.format(pattern), pwd)
                if s is None:
                    good_pwd = False
        print(pwd)
        
    def _decrypt(self):
        if len(self.ciphertext) == 0:
            return bytes([])
        iv = bytes(self.ciphertext[:16])
        y = bytes(self.ciphertext[16:])
        obj = AES.new(self.key, AES.MODE_CBC, iv)
        x = obj.decrypt(y)
        x = x[:x.index(255)]
        return x
    
    def _clear(self, x0=None, params=None):
        os.system('clear')
    
    def _save(self, x0=None, params=None):
        iv, cont = self._encrypt()
        with open(self.filename, 'wb') as f:
            f.write(iv+cont)
        print('saved {}'.format(self.filename))
    
    def _encrypt(self):
        iv = bytes([random.randint(0,255) for _ in range(16)])
        obj = AES.new(self.key, AES.MODE_CBC, iv)
        rem = (-len(self.content)) % 16
        self.content = self.content + bytes([255 for _ in range(rem)])
        return (iv, obj.encrypt(self.content))
    
    def _change_key(self, x0=None, params=None):
        self._get_password()
    
    def _get_first(self, x_list, default=''):
        if len(x_list)==0:
            return default
        return x_list[0]
    
    def _get_second(self, x_list, default=''):
        if len(x_list)<2:
            return default
        return x_list[1]

if __name__ == '__main__':
    pwh = PasswordHandler(args.input_file)
    
    
