# Krypton Test Matrix

## Strategy Matrix

- Dispatcher discovery robustness across sparse and dense handler layouts
- Opcode mapping confidence and semantic repair convergence
- Semantic validator strictness: default vs. more aggressive unresolved-byte cleanup

## Automated Checks

- `dotnet test Krypton.sln`
  - Runs assembly load smoke test for managed PE output compatibility.
  - Runs sample-based regression for known local samples (`Crackme.exe`, `awesome_msil.exe`, `Offline_sales_bills_msil.exe`, `WindowsFormsApplication41.exe`) when present.

## IL Verification Pass

Use IL verification on rebuilt assemblies (outside this unit test project):

1. Run Krypton:
   - `dotnet run --project Krypton/Krypton.csproj -- <sample.exe>`
2. Verify emitted assembly:
   - `ilverify <sample-Devirtualized.exe> -r <runtime refs>`

If `ilverify` is not installed globally, install it as a .NET tool first.
