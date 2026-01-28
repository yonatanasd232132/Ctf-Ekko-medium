import sys

def solve_phantom(dump_file):
    # The key found via Format String or Time Trigger
    KEY = 0xDEADC0DE
    # Convert key to little-endian bytes (Windows standard)
    KEY_BYTES = KEY.to_bytes(4, byteorder='little')
    
    print(f"[*] Reading {dump_file}...")
    with open(dump_file, 'rb') as f:
        data = bytearray(f.read())

    print("[*] Brute-force decrypting (Rolling XOR)...")
    
    # OPTIMIZATION: Instead of XORing the whole 500MB+ dump, 
    # we scan for the encrypted version of the flag prefix "CTF{".
    #
    # We don't know the alignment (index % 4), so we try all 4 offsets.
    
    target_prefix = b"CTF{"
    
    for offset in range(4):
        # Create a test key rotated by the offset
        test_key = KEY_BYTES[offset:] + KEY_BYTES[:offset]
        
        # Calculate what "CTF{" looks like when XORed with this alignment
        encrypted_target = bytearray()
        for i in range(len(target_prefix)):
            encrypted_target.append(target_prefix[i] ^ test_key[i % 4])
            
        print(f"[-] Checking offset {offset}, looking for hex: {encrypted_target.hex()}")
        
        # Search the dump for this encrypted byte sequence
        idx = data.find(encrypted_target)
        
        if idx != -1:
            print(f"[+] FOUND Candidate at offset {hex(idx)}!")
            
            # Decrypt a chunk around this location to get the full flag
            decrypted_text = ""
            # We grab 50 bytes to be safe
            for i in range(50):
                enc_byte = data[idx + i]
                # Re-calculate correct key byte based on absolute position
                key_byte = KEY_BYTES[(idx + i) % 4]
                decrypted_text += chr(enc_byte ^ key_byte)
                
            print(f"\nSUCCESS! Flag found:\n{decrypted_text}\n")
            return

    print("[-] Flag not found in dump. Was the process sleeping when you dumped it?")

# Usage: python solve.py phantom.DMP
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python solve.py <path_to_dump>")
    else:
        solve_phantom(sys.argv[1])