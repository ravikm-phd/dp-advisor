"""Walk-through of dp_advice on diffprivlib's Laplace mechanism.

Run with:  python examples/demo.py
"""

import diffprivlib.mechanisms as dp_mech

from dp_advice import (
    defadvice,
    patch_dp_mechanism, unpatch_dp_mechanism,
    default_accountant, default_logger,
    BudgetExhaustedError, NISTValidationError, ParameterMismatchError
)

def main():
    print("=" * 70)
    print("      DP-ADVICE: DYNAMIC PRIVACY ENFORCEMENT FRAMEWORK DEMO")
    print("      Checks informed by NIST SP 800-226")
    print("=" * 70)

    # total budget of 3.0, pure DP only
    default_accountant.set_budget(epsilon=3.0, delta=0.0)
    print(f"\n[+] Global Privacy Accountant Initialized. Budget Cap: Epsilon = {default_accountant.total_epsilon}")

    key = "diffprivlib.mechanisms.Laplace.randomise"
    patch_dp_mechanism(dp_mech.Laplace, "randomise", key)

    @defadvice(key, name="custom_data_sanitizer", advice_type=":before")
    def custom_before_check(value, *args, **kwargs):
        print(f"    [-> :before Advice] Inspecting input value={value} before mechanism execution.")

    @defadvice(key, name="custom_post_auditor", advice_type=":after")
    def custom_after_audit(result, *args, **kwargs):
        print(f"    [<- :after Advice] Output mechanism returned noisy value={result:.6f}")

    print("\n--- TEST 1: Valid DP Queries within Budget Envelope ---")
    val1 = dp_mech.Laplace(epsilon=1.0, sensitivity=1.0).randomise(42.0)
    print(f"Result Query 1: {val1:.4f} | Account Status: {default_accountant.get_status()}")

    val2 = dp_mech.Laplace(epsilon=1.5, sensitivity=1.0).randomise(100.0)
    print(f"Result Query 2: {val2:.4f} | Account Status: {default_accountant.get_status()}")

    print("\n--- TEST 2: Budget Exhaustion (refused at the reservation step) ---")
    try:
        # only 0.5 left at this point
        dp_mech.Laplace(epsilon=1.0, sensitivity=1.0).randomise(15.0)
    except BudgetExhaustedError as e:
        print(f"    [!] Refused: {e}")

    print("\n--- TEST 3: Parameter Check (refused before any budget is reserved) ---")
    try:
        dp_mech.Laplace(epsilon=15.0, sensitivity=1.0).randomise(10.0)
    except NISTValidationError as e:
        print(f"    [!] Refused: {e}")

    print("\n--- TEST 4: Caller Cannot Under-Report Epsilon ---")
    try:
        dp_mech.Laplace(epsilon=0.5, sensitivity=1.0).randomise(10.0, epsilon=0.01)
    except ParameterMismatchError as e:
        print(f"    [!] Refused: {e}")

    print(f"\n[+] Final Privacy Accountant Status: {default_accountant.get_status()}")
    print(f"[+] Audit Log Written to: {default_logger.log_file}")

    unpatch_dp_mechanism(dp_mech.Laplace, "randomise")
    print("[+] Laplace mechanism unpatched.")
    print("=" * 70)
    print("      DEMO COMPLETED")
    print("=" * 70)

if __name__ == "__main__":
    main()
