using Microsoft.VisualStudio.TestTools.UnitTesting;
using Bittrex.Helpers;

namespace UnitTests
{
    [TestClass]
    public class ApiConfigTests
    {
        [TestMethod]
        public void ConfigRetrieverIsRegistryByDefault()
        {
            Assert.IsInstanceOfType(HttpUtilities.ConfigRetriever, typeof(ConfigRetrieverRegistry));
            HttpUtilities.ConfigRetriever = new ConfigRetrieverConfigFile();
            Assert.IsInstanceOfType(HttpUtilities.ConfigRetriever, typeof(ConfigRetrieverConfigFile));
        }

        [TestMethod]
        public void AppConfigConfigurationIsDefined()
        {
            Assert.IsTrue(new ConfigRetrieverConfigFile().HasConfig);
        }

        /// <summary>
        ///  Runs against the registry, if not set up, will fail.
        /// </summary>
        [TestMethod]
        [Ignore()]
        public void AppConfigRegistryIsDefined()
        {
            Assert.IsTrue(new ConfigRetrieverRegistry().HasConfig);
        }        
    }
}
