#!/usr/bin/env python3
import csv

def label_csv(input_file, output_file, label):
    with open(input_file, 'r') as inf, open(output_file, 'w', newline='') as outf:
        reader = csv.DictReader(inf)
        fieldnames = reader.fieldnames
        
        writer = csv.DictWriter(outf, fieldnames=fieldnames)
        writer.writeheader()
        
        for row in reader:
            row['label'] = label
            writer.writerow(row)
    
    print(f"✓ Labeled {input_file} -> {output_file}")

# Label all three files
label_csv('validation/samples/express_sample.csv', 
          'validation/samples/express_sample_labeled.csv', 
          'NON_ACTIONABLE')

label_csv('validation/samples/lodash_sample.csv', 
          'validation/samples/lodash_sample_labeled.csv', 
          'ACTIONABLE')

label_csv('validation/samples/semgrep-backend_sample.csv', 
          'validation/samples/semgrep-backend_sample_labeled.csv', 
          'ACTIONABLE')

print("\n✓ All files labeled!")
