using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fido_Main.Main.Detectors
{
    class CyphortAlerts_Global
    {
        public int iVer;

        public static void GetCyphortAlerts()
        {
            Console.WriteLine(@"Running Cyphort v" + iVer + " detector.");

            //currently needed to bypass site without a valid cert.
            //todo: make ssl bypass configurable
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs("cyphortv" + iVer);
            var request = parseConfigs.Server + parseConfigs.Query + parseConfigs.APIKey;
            var alertRequest = (HttpWebRequest)WebRequest.Create(request);
            alertRequest.Method = "GET";
            try
            {
                using (var cyphortResponse = alertRequest.GetResponse() as HttpWebResponse)
                {
                    if (cyphortResponse != null && cyphortResponse.StatusCode == HttpStatusCode.OK)
                    {
                        using (var respStream = cyphortResponse.GetResponseStream())
                        {
                            if (respStream == null) return;
                            var cyphortReader = new StreamReader(respStream, Encoding.UTF8);
                            var stringreturn = cyphortReader.ReadToEnd();

                            _ParseCyphort();

                            var responseStream = cyphortResponse.GetResponseStream();
                            if (responseStream != null) responseStream.Dispose();
                            cyphortResponse.Close();
                            Console.WriteLine(@"Finished processing Cyphort detector.");
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Cyphort Detector getting json:" + e);
            }
        }

private static _ParseCyphort()
        {
            var cyphortReturn = JsonConvert.DeserializeObject<CyphortClass>(stringreturn);
            if (cyphortReturn.correlations_array.Any() | cyphortReturn.infections_array.Any() | cyphortReturn.downloads_array.Any())
            {
                ParseCyphort(cyphortReturn);
            }
        }

    }
}
