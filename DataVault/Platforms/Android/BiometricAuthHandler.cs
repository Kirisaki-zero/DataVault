// BiometricAuthHandler.cs
using AndroidX.Biometric;
using AndroidX.Fragment.App;

public class BiometricAuthHandler
{
    public Task<bool> AuthenticateAsync(FragmentActivity activity)
    {
        var tcs = new TaskCompletionSource<bool>();

        var executor   = ContextCompat.GetMainExecutor(activity);
        var biometric  = new BiometricPrompt(activity, executor,
            new AuthCallback(tcs));

        var promptInfo = new BiometricPrompt.PromptInfo.Builder()
            .SetTitle("Vault Authentication")
            .SetSubtitle("Konfirmasi identitas Anda")
            .SetNegativeButtonText("Gunakan PIN")
            .Build();

        biometric.Authenticate(promptInfo);
        return tcs.Task;
    }
}