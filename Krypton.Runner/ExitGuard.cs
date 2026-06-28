using System;
using System.Reflection;
using System.Windows.Forms;
using HarmonyLib;

namespace Krypton.Runner
{
    /// <summary>
    /// Thrown by the Harmony patch on Environment.Exit so the caller can catch it.
    /// This prevents the child snapshot process from being killed by NET Reactor's
    /// anti-tamper guard and allows reading partially-initialized form state.
    /// </summary>
    public sealed class ProtectedExitException : Exception
    {
        public int ExitCode { get; }

        public ProtectedExitException(int exitCode)
            : base($"Protected assembly called Environment.Exit({exitCode})")
        {
            ExitCode = exitCode;
        }
    }

    internal enum ExitGuardBehavior
    {
        Throw,
        Suppress
    }

    /// <summary>
    /// Installs and manages the two Harmony patches needed for form snapshot:
    ///
    ///   1. Environment.Exit  → throws ProtectedExitException instead of killing the process.
    ///   2. Form..ctor (per type) → records the `this` pointer BEFORE the constructor body
    ///      runs, so we have a handle to the partially-initialized form even when the
    ///      constructor never returns normally.
    /// </summary>
    internal static class ExitGuard
    {
        private static Harmony _harmony;

        // Stores the most recently created Form instance PER THREAD.
        // Updated by the constructor prefix; read back after catching ProtectedExitException.
        [ThreadStatic]
        public static Form CurrentInstance;

        [ThreadStatic]
        public static Form CapturedRunForm;

        public static ExitGuardBehavior Behavior { get; set; } = ExitGuardBehavior.Throw;
        public static int? LastExitCode { get; private set; }

        /// <summary>
        /// Install Harmony patches.  Must be called once, before any target assembly code runs.
        /// </summary>
        public static void Install()
        {
            if (_harmony != null) return;

            _harmony = new Harmony("krypton.runner.exitguard");

            // Patch 1: Environment.Exit → ProtectedExitException
            var exitMethod = typeof(Environment).GetMethod("Exit",
                BindingFlags.Public | BindingFlags.Static,
                null, new[] { typeof(int) }, null);

            if (exitMethod != null)
            {
                _harmony.Patch(
                    exitMethod,
                    prefix: new HarmonyMethod(typeof(ExitGuard).GetMethod(nameof(ExitPrefix))));
            }

        }

        /// <summary>
        /// Dynamically patch the parameterless constructor of a specific Form subtype
        /// so we can track the instance pointer before the body executes.
        /// Must be called after Install() and before the type is instantiated.
        /// </summary>
        public static void TrackFormType(Type formType)
        {
            if (_harmony == null) return;

            var ctor = formType.GetConstructor(
                BindingFlags.Public | BindingFlags.Instance,
                null, Type.EmptyTypes, null);

            if (ctor == null) return;

            try
            {
                _harmony.Patch(
                    ctor,
                    prefix: new HarmonyMethod(
                        typeof(ExitGuard).GetMethod(nameof(FormCtorPrefix))));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ExitGuard] Could not patch ctor of {formType.Name}: {ex.Message}");
            }
        }

        // ── Harmony patch bodies (must be public static) ──────────────────

        /// <summary>
        /// Prefix for Environment.Exit — convert the exit into a catchable exception.
        /// Returning false prevents the original method from executing.
        /// </summary>
        public static bool ExitPrefix(int exitCode)
        {
            LastExitCode = exitCode;
            if (Behavior == ExitGuardBehavior.Suppress)
                return false;

            throw new ProtectedExitException(exitCode);
        }

        /// <summary>
        /// Prefix for Form..ctor — store the not-yet-constructed `this` reference.
        /// Harmony provides __instance even for constructors (memory is allocated,
        /// fields are not yet initialized, but the reference is valid).
        /// </summary>
        public static void FormCtorPrefix(object __instance)
        {
            if (__instance is Form form)
                CurrentInstance = form;
        }

        public static void Uninstall()
        {
            _harmony?.UnpatchAll("krypton.runner.exitguard");
            _harmony = null;
        }
    }
}
