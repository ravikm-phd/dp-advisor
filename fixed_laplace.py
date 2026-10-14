import numpy as np
import diffprivlib.mechanisms as dp_mech

salaries = np.array([50000, 70000, 45000, 60000, 55000])
lower_bound, upper_bound = 0.0, 100000.0

# 1. Compute exact mean salary
raw_mean = np.mean(salaries)

# 2. Sensitivity for mean query: Delta f = (U - L) / N
sensitivity = (upper_bound - lower_bound) / len(salaries)

# 3. Execute 1 single query release (Consumes only 1.0 total epsilon!)
mech = dp_mech.Laplace(epsilon=1.0, sensitivity=sensitivity)
dp_mean_salary = mech.randomise(raw_mean)
print("Differentially Private Mean Salary:", dp_mean_salary)
