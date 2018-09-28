# David Horowitz 
#I pledge my honor that I have abided by the Stevens honor system
#OTP breaker (key resuse)
import string
import hashlib
c0 = '2d0a0612061b0944000d161f0c1746430c0f0952181b004c1311080b4e07494852'
c1 = "200a054626550d051a48170e041d011a001b470204061309020005164e15484f44"
c2 = "3818101500180b441b06004b11104c064f1e0616411d064c161b1b04071d460101"
c3 = "200e0c4618104e071506450604124443091b09520e125522081f061c4e1d4e5601"
c4 = "304f1d091f104e0a1b48161f101d440d1b4e04130f5407090010491b061a520101"
c5 = "2d0714124f020111180c450900595016061a02520419170d1306081c1d1a4f4601"
c6 = "351a160d061917443b3c354b0c0a01130a1c01170200191541070c0c1b01440101"
c7 = "3d0611081b55200d1f07164b161858431b0602000454020d1254084f0d12554249"
c8 = "340e0c040a550c1100482c4b0110450d1b4e1713185414181511071b071c4f0101"
c9 = "2e0a5515071a1b081048170e04154d1a4f020e0115111b4c151b492107184e5201"
c10 = "370e1d4618104e05060d450f0a104f044f080e1c04540205151c061a1a5349484c"

ciphertexts = [c0, c1, c2, c3, c4, c5 ,c6 ,c7 ,c8 , c9, c10] #array of all ciphertexts

#finds the xor of 2 hex's and returns ascii 
def str_xor(hex1, hex2):
    result = "".join(["%x" % (int(x,16) ^ int(y,16)) for (x, y) in zip(hex1, hex2)])
    return bytes.fromhex(result).decode()

possible_space_indexes = {} #stores how many space chars are found
for ciphertext in ciphertexts:
    possible_space_indexes[ciphertext] = [0] * 33

found_key = [None] * 33 #chars of the key that are found 
known_key_indexes = [] #indexes for parts of the key that are known 

for ciphertext in ciphertexts: #for each ciphertext
    
    for ciphertext2 in ciphertexts: # go through each other ciphertext
        if(ciphertext != ciphertext2):
            for charindex, char in enumerate(str_xor(ciphertext, ciphertext2)): #grab each char and charindex from the xor of the selected ciphertexts
                if char in string.printable and char.isalpha(): #if the char is a printable character and is alphanumeric 
                    possible_space_indexes[ciphertext][charindex] += 1 #add one to the counter for number of times a character can possibly be seen as a space
    known_space_indexes = []

    for index, value in enumerate(possible_space_indexes[ciphertext]): #for each char in the current ciphertext
        if value >= 6: #if the value of the counter is at least 6
            known_space_indexes.append(index) #append the index to the list of known indexes 

    space_xor = str_xor(ciphertext, "20"*33) #xor the current ciphertext with a string of all space chars
    for index in known_space_indexes: #for each index
        found_key[index] ='{:02X}'.format(ord(space_xor[index])) #convert xor back to hex
        known_key_indexes.append(index) #add the index to the known key indexes

found_key_final = ''.join([val if val is not None else '00' for val in found_key]) #create the final key from the vals in found_key, if the val wasn't found put 00
output = str_xor(found_key_final, c0) #xor the found key with the target ciphertext
print(''.join([char if index in known_key_indexes else '#' for index, char in enumerate(output)])) #print out the xor result, if the char isn't known put a #

#manually observe key 
#result was: #esting #est#ng can you read t#i>
p0 = "testing testing can you read this" #manually found key by reading line 52

key = "596f75666f756e647468656b657921636f6e67726174756c6174696f6e73212121" #xor of p0 and c0

for ciphertext in ciphertexts: #xor each ciphertext with the final key
    print(str_xor(key, ciphertext))


hex_dig = key
for _ in range(14): #solves the problem of the key changing nightly for 2 weeks
    hex_dig = bytes(hex_dig, encoding="ascii")
    hash_object = hashlib.sha256(hex_dig)
    hex_dig = hash_object.hexdigest()
    hex_dig = str(hex_dig)
    hex_dig = hex_dig + "00100001"

print(hex_dig)