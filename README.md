# Set-RBCDBytes

This will set the msds-allowedtoactonbehalfofotheridentity property on the target with the security descriptor for a supplied user or machine that has an SPN.

**Usage:** 

Set-RBCDBytes -Domain LAB.LOCAL -TargetComputer LABWIN10 -Principal 'LABWIN10$'


Set-RBCDBytes -Domain LAB.LOCAL -TargetComputer LABWIN10 -Principal Bob

