with open(r'E:\data\archive2\NF-UQ-NIDS-v2.csv', 'r', encoding='ascii') as f: header = f.readline().strip()
for i, line in enumerate(f, 2): 
    if line.strip() == header: print(f'Header repeated at line {i}'); 
    if i > 1000000: 
        break