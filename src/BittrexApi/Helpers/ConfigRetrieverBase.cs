using System;
using Microsoft.Win32;
using System.Configuration;

namespace Bittrex.Helpers
{
    public abstract class ConfigRetrieverBase
    {
        public abstract bool HasConfig { get; }
        protected abstract Tuple<string, string> GetApiKeyAndSecret();

        public Tuple<string, string> GetApiAndSecret()
        {
            var apiAndSecret = GetApiKeyAndSecret();
            if (apiAndSecret == null)
            {
                throw new Exception("ApiKey/ApiSecret not specified");
            }
            return apiAndSecret;
        }

        public const string ApiRegistryPathLocalMachine = @"Software\Bittrex";
        public const string ApiRegistryPathCurrentUser = @"Software\Bittrex";
        public const string ApiRegistryPathApiKey = @"ApiKey";
        public const string ApiRegistryPathApiSecret = @"ApiSecret";
        public const string ApiConfigurationApiKey = "BittrexApiKey";
        public const string ApiConfigurationApiSecret = "BittrexApiSecret";
    }

    public class ConfigRetrieverRegistry : ConfigRetrieverBase
    {
        public RegistryView View = RegistryView.Registry32;
        public override bool HasConfig
        {
            get
            {
                using (var bittrexRegKey = 
                        RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, View).OpenSubKey(ApiRegistryPathLocalMachine) 
                        ?? RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, View).OpenSubKey(ApiRegistryPathCurrentUser))
                {
                    if (bittrexRegKey == null)
                    {
                        return false;
                    }
                    return !string.IsNullOrWhiteSpace(bittrexRegKey.GetValue(ApiRegistryPathApiKey) as string)
                        && !string.IsNullOrWhiteSpace(bittrexRegKey.GetValue(ApiRegistryPathApiSecret) as string);
                }
            }
        }
        
        protected override Tuple<string, string> GetApiKeyAndSecret()
        {
            string apiKey = null;
            string apiSecret = null;

            using (var bittrexRegKey = Registry.LocalMachine.OpenSubKey(ApiRegistryPathLocalMachine))
            {
                if (bittrexRegKey != null)
                {
                    apiKey = bittrexRegKey.GetValue(ApiRegistryPathApiKey) as string;
                    apiSecret = bittrexRegKey.GetValue(ApiRegistryPathApiSecret) as string;
                }
            }

            if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(apiSecret))
            {
                using (var bittrexRegKey = Registry.CurrentUser.OpenSubKey(ApiRegistryPathCurrentUser))
                {
                    if (bittrexRegKey != null)
                    {
                        apiKey = bittrexRegKey.GetValue(ApiRegistryPathApiKey) as string;
                        apiSecret = bittrexRegKey.GetValue(ApiRegistryPathApiSecret) as string;
                    }
                }
            }

            if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(apiSecret))
            {
                return null;
            }

            return new Tuple<string, string>(apiKey, apiSecret);
        }
    }
    
    public class ConfigRetrieverConfigFile : ConfigRetrieverBase
    {
        public override bool HasConfig
        {
            get
            {
                return !string.IsNullOrWhiteSpace(ConfigurationManager.AppSettings[ApiConfigurationApiKey]) 
                        && !string.IsNullOrWhiteSpace(ConfigurationManager.AppSettings[ApiConfigurationApiSecret]);
            }
        }

        protected override Tuple<string, string> GetApiKeyAndSecret()
        {
            if (!HasConfig)
            {
                return null;
            }
            return new Tuple<string, string>(ConfigurationManager.AppSettings[ApiConfigurationApiKey], ConfigurationManager.AppSettings[ApiConfigurationApiSecret]);
        }
    }
}
