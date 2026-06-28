using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace Krypton.Runner
{
    /// <summary>
    /// Captures the exact runtime state of WinForms Form instances by constructing
    /// them (without showing) and reading back all relevant property values.
    /// This gives us the ground-truth values (ClientSize, FormBorderStyle,
    /// StartPosition, etc.) that the original InitializeComponent set.
    ///
    /// When NET Reactor calls Environment.Exit() from inside the constructor,
    /// ExitGuard converts it to a ProtectedExitException so we can recover the
    /// partially-initialized form instance that the constructor prefix stored.
    /// </summary>
    internal static class FormSnapshot
    {
        public static List<FormEntry> CaptureFromEntryPoint(Assembly assembly)
        {
            var results = new List<FormEntry>();
            var entryPoint = assembly.EntryPoint;
            if (entryPoint == null)
                return results;

            Form captured = null;
            Exception error = null;

            var thread = new Thread(() =>
            {
                EventHandler idleHandler = null;
                try
                {
                    ExitGuard.CapturedRunForm = null;
                    idleHandler = (sender, idleArgs) =>
                    {
                        try
                        {
                            if (captured != null)
                                return;

                            foreach (Form form in Application.OpenForms)
                            {
                                captured = form;
                                ExitGuard.CapturedRunForm = form;
                                break;
                            }

                            if (captured != null)
                                Application.ExitThread();
                        }
                        catch (Exception ex)
                        {
                            error = ex;
                            Application.ExitThread();
                        }
                    };
                    Application.Idle += idleHandler;

                    var parameters = entryPoint.GetParameters();
                    object[] args = parameters.Length == 0
                        ? null
                        : new object[] { new string[0] };

                    entryPoint.Invoke(null, args);
                    captured = captured ?? ExitGuard.CapturedRunForm;
                }
                catch (TargetInvocationException tie)
                {
                    error = tie.InnerException ?? tie;
                    captured = ExitGuard.CapturedRunForm;
                }
                catch (Exception ex)
                {
                    error = ex;
                    captured = ExitGuard.CapturedRunForm;
                }
                finally
                {
                    if (idleHandler != null)
                        Application.Idle -= idleHandler;
                }
            });

            thread.SetApartmentState(ApartmentState.STA);
            thread.IsBackground = true;
            thread.Start();
            thread.Join(TimeSpan.FromSeconds(10));

            if (thread.IsAlive)
            {
                Console.WriteLine("[Runner]   EntryPoint thread hung - skipping entrypoint snapshot.");
                thread.Abort();
                return results;
            }

            if (error != null)
            {
                Console.WriteLine(
                    $"[Runner]   EntryPoint snapshot error: {error.GetType().Name}: {error.Message}");
            }

            if (captured == null)
                return results;

            try
            {
                var entry = ReadFormProperties(captured, captured.GetType());
                if (entry != null)
                    results.Add(entry);
            }
            finally
            {
                try { captured.Dispose(); } catch { /* ignore */ }
            }

            return results;
        }

        public static List<FormEntry> CaptureAll(Assembly assembly)
        {
            var results = new List<FormEntry>();

            Type[] types;
            try { types = assembly.GetTypes(); }
            catch (ReflectionTypeLoadException e) { types = e.Types; }

            foreach (var t in types)
            {
                if (t == null || t.IsAbstract || t.ContainsGenericParameters) continue;
                if (!typeof(Form).IsAssignableFrom(t)) continue;

                Console.WriteLine($"[Runner]   Form found: {t.FullName}");
                var entry = CaptureForm(t);
                if (entry != null)
                    results.Add(entry);
            }

            return results;
        }

        private static FormEntry CaptureForm(Type formType)
        {
            FormEntry result = null;

            // Register a constructor prefix BEFORE starting the STA thread so that
            // ExitGuard.CurrentInstance is populated even when Exit fires inside ctor.
            ExitGuard.TrackFormType(formType);

            var thread = new Thread(() =>
            {
                Form form = null;
                try
                {
                    form = (Form)Activator.CreateInstance(formType);
                    result = ReadFormProperties(form, formType);
                }
                catch (TargetInvocationException tie)
                    when (tie.InnerException is ProtectedExitException pex)
                {
                    // NET Reactor called Environment.Exit() from inside the constructor.
                    // The constructor prefix already stored `this` in ExitGuard.CurrentInstance
                    // before the body ran, so we can read whatever was initialized so far.
                    Console.WriteLine(
                        $"[Runner]   Form({formType.Name}) called Environment.Exit({pex.ExitCode})" +
                        " — reading partial state.");

                    form = ExitGuard.CurrentInstance;
                    if (form != null)
                        result = ReadFormProperties(form, formType);
                    else
                        Console.WriteLine("[Runner]   No partial form instance captured.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine(
                        $"[Runner]   Form construction error ({formType.Name}):" +
                        $" {ex.GetType().Name}: {ex.Message}");
                    if (ex.InnerException != null)
                        Console.WriteLine(
                            $"[Runner]     Inner: {ex.InnerException.GetType().Name}:" +
                            $" {ex.InnerException.Message}");
                }
                finally
                {
                    try { form?.Dispose(); } catch { /* ignore */ }
                }
            });

            thread.SetApartmentState(ApartmentState.STA);
            thread.IsBackground = true;
            thread.Start();
            thread.Join(TimeSpan.FromSeconds(10));

            if (!thread.IsAlive) return result;

            // Thread hung — form might be showing a message loop; abort and report
            Console.WriteLine($"[Runner]   Form thread hung ({formType.Name}) — skipping.");
            thread.Abort();
            return null;
        }

        private static FormEntry ReadFormProperties(Form form, Type formType)
        {
            var entry = new FormEntry
            {
                TypeName      = formType.FullName,
                TypeToken     = $"0x{formType.MetadataToken:X8}",
                Text          = SafeGet(() => form.Text),
                ClientWidth   = SafeGet(() => form.ClientSize.Width),
                ClientHeight  = SafeGet(() => form.ClientSize.Height),
                FormBorderStyle = SafeGet(() => (int)form.FormBorderStyle),
                StartPosition = SafeGet(() => (int)form.StartPosition),
                MaximizeBox   = SafeGet(() => form.MaximizeBox),
                MinimizeBox   = SafeGet(() => form.MinimizeBox),
                AutoScaleMode = SafeGet(() => (int)form.AutoScaleMode),
                AutoScaleDimensionsX = SafeGet(() => form.AutoScaleDimensions.Width),
                AutoScaleDimensionsY = SafeGet(() => form.AutoScaleDimensions.Height),
            };

            try
            {
                foreach (Control ctrl in form.Controls)
                {
                    var ce = ReadControlProperties(form, ctrl);
                    if (ce != null) entry.Controls.Add(ce);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Runner]   Could not enumerate controls: {ex.Message}");
            }

            Console.WriteLine(
                $"[Runner]   Captured form: Text='{entry.Text}' " +
                $"ClientSize=({entry.ClientWidth},{entry.ClientHeight}) " +
                $"Border={entry.FormBorderStyle} Start={entry.StartPosition} " +
                $"MaxBox={entry.MaximizeBox} MinBox={entry.MinimizeBox} " +
                $"Controls={entry.Controls.Count}");

            return entry;
        }

        private static ControlEntry ReadControlProperties(Form owner, Control ctrl)
        {
            var field = FindControlField(owner, ctrl);
            var entry = new ControlEntry
            {
                TypeName   = ctrl.GetType().FullName,
                FieldName  = field?.Name,
                FieldToken = field == null ? null : $"0x{field.MetadataToken:X8}",
                Name       = SafeGet(() => ctrl.Name),
                Text       = SafeGet(() => ctrl.Text),
                Left       = ctrl.Left,
                Top        = ctrl.Top,
                Width      = ctrl.Width,
                Height     = ctrl.Height,
                TabIndex   = ctrl.TabIndex,
                Anchor     = SafeGet(() => (int)ctrl.Anchor),
                PasswordChar = ctrl is TextBox tb ? (int)tb.PasswordChar : 0,
                UseVisualStyleBackColor = ctrl is ButtonBase btn
                    ? (bool?)btn.UseVisualStyleBackColor : null,
            };

            try
            {
                foreach (Control child in ctrl.Controls)
                {
                    var childEntry = ReadControlProperties(owner, child);
                    if (childEntry != null) entry.Controls.Add(childEntry);
                }
            }
            catch { /* best effort */ }

            return entry;
        }

        private static FieldInfo FindControlField(Form owner, Control ctrl)
        {
            var type = owner.GetType();
            while (type != null && type != typeof(Form))
            {
                foreach (var field in type.GetFields(
                    BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
                {
                    if (!typeof(Control).IsAssignableFrom(field.FieldType))
                        continue;

                    try
                    {
                        if (ReferenceEquals(field.GetValue(owner), ctrl))
                            return field;
                    }
                    catch { /* inaccessible field - ignore */ }
                }

                type = type.BaseType;
            }

            return null;
        }

        private static T SafeGet<T>(Func<T> fn, T fallback = default)
        {
            try { return fn(); }
            catch { return fallback; }
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // JSON models for form snapshots
    // ──────────────────────────────────────────────────────────────────

    public sealed class FormEntry
    {
        public string TypeName { get; set; }
        public string TypeToken { get; set; }   // "0x02xxxxxx"

        // Form-level properties (exact runtime values)
        public string Text { get; set; }
        public int? ClientWidth { get; set; }
        public int? ClientHeight { get; set; }
        public int? FormBorderStyle { get; set; }   // System.Windows.Forms.FormBorderStyle enum value
        public int? StartPosition { get; set; }     // FormStartPosition enum value
        public bool? MaximizeBox { get; set; }
        public bool? MinimizeBox { get; set; }
        public int? AutoScaleMode { get; set; }     // AutoScaleMode enum value
        public float? AutoScaleDimensionsX { get; set; }
        public float? AutoScaleDimensionsY { get; set; }

        public List<ControlEntry> Controls { get; set; } = new List<ControlEntry>();
    }

    public sealed class ControlEntry
    {
        public string TypeName { get; set; }
        public string FieldName { get; set; }
        public string FieldToken { get; set; }
        public string Name { get; set; }
        public string Text { get; set; }
        public int Left { get; set; }
        public int Top { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public int TabIndex { get; set; }
        public int Anchor { get; set; }           // AnchorStyles enum value
        public int PasswordChar { get; set; }     // 0 if not a TextBox or no password char
        public bool? UseVisualStyleBackColor { get; set; }
        public List<ControlEntry> Controls { get; set; } = new List<ControlEntry>();
    }
}
