using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace AndroidAnalysis
{
    public class NetworkSecurityDto
    {
        public string Scope { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
    }
    public class NetworkSecurity
    {

        string networksecurityfilepath = @"C:\Users\bishn\Downloads\apks\5b40b49cd80dbe20ba611d32045b57c6\resources\res\xml\network_security_config.xml";
        public List<NetworkSecurityDto> finds = new List<NetworkSecurityDto>() { };
        public List<NetworkSecurityDto> start()
        {
            try
            {
                XmlDocument doc = new();
                doc.Load(networksecurityfilepath);

                XmlNodeList b_cfg = doc.GetElementsByTagName("base-config");
                if (b_cfg.Count > 0)
                {
                    foreach (XmlElement item in b_cfg)
                    {
                        if (item.GetAttribute("cleartextTrafficPermitted") == "true")
                        {
                            finds.Add(new NetworkSecurityDto()
                            {
                                Description = "Base config is insecurely configured to permit clear text traffic to all domains.",
                                Scope = "['*']",
                                Severity = "HIGH"
                            });
                        }
                        if (item.GetAttribute("cleartextTrafficPermitted") == "false")
                        {
                            finds.Add(new NetworkSecurityDto()
                            {
                                Description = "Base config is configured to disallow clear text traffic to all domains.",
                                Scope = "['*']",
                                Severity = "SECURE"
                            });
                        }

                        try
                        {
                            XmlNodeList trst_anch = item.GetElementsByTagName("trust-anchors");
                            if (trst_anch.Count > 0)
                            {
                                foreach (XmlElement trst_anch_inner in trst_anch)
                                {
                                    XmlNodeList certs = trst_anch_inner.GetElementsByTagName("certificates");
                                    foreach (XmlElement cert in certs)
                                    {
                                        string loc = cert.GetAttribute("src");
                                        string over_ride = cert.GetAttribute("overridePins");
                                        if (loc.Contains("@raw/"))
                                        {
                                            finds.Add(new NetworkSecurityDto()
                                            {
                                                Description = $"Base config is configured to trust bundled certs {loc}.",
                                                Scope = "['*']",
                                                Severity = "INFO"
                                            });
                                        }
                                        else if (loc == "system")
                                        {
                                            finds.Add(new NetworkSecurityDto()
                                            {
                                                Description = $"Base config is configured to trust  system certificates.",
                                                Scope = "['*']",
                                                Severity = "WARNING"
                                            });
                                        }
                                        else if (loc == "user")
                                        {
                                            finds.Add(new NetworkSecurityDto()
                                            {
                                                Description = $"Base config is configured to trust user installed certificates.",
                                                Scope = "['*']",
                                                Severity = "WARNING"
                                            });
                                        }
                                        if (over_ride == "true")
                                        {
                                            finds.Add(new NetworkSecurityDto()
                                            {
                                                Description = $"Base config is configured to bypass certificate pinning.",
                                                Scope = "['*']",
                                                Severity = "HIGH"
                                            });
                                        }

                                    }

                                }
                            }
                        }
                        catch (Exception)
                        {
                        }

                    }
                }


                XmlNodeList dom_cfg = doc.GetElementsByTagName("domain-config");

                foreach (XmlElement cfg in dom_cfg)
                {
                    XmlNodeList domains = cfg.GetElementsByTagName("domain");
                    List<string> domain_list = new List<string>() { };

                    foreach (XmlElement dom in domains)
                    {
                        domain_list.Add(dom?.FirstChild?.Value);
                    }
                    try
                    {

                        if (cfg.GetAttribute("cleartextTrafficPermitted") == "true")
                        {
                            finds.Add(new NetworkSecurityDto()
                            {
                                Description = $"Domain config is insecurely configured to permit clear text traffic to these domains in scope.",
                                Scope = string.Join(",", domain_list.ToArray()),
                                Severity = "HIGH"
                            });
                        }
                        else if (cfg.GetAttribute("cleartextTrafficPermitted") == "false")
                        {
                            finds.Add(new NetworkSecurityDto()
                            {
                                Description = $"Domain config is securely configured to disallow clear text traffic to these domains in scope.",
                                Scope = string.Join(",", domain_list.ToArray()),
                                Severity = "SECURE"
                            });
                        }
                    }
                    catch (Exception)
                    {

                    }
                    XmlNodeList dtrust = cfg.GetElementsByTagName("trust-anchors");
                    try
                    {
                        foreach (XmlElement dtrustitem in dtrust)
                        {
                            XmlNodeList certs = dtrustitem.GetElementsByTagName("certificates");
                            foreach (XmlElement certitem in certs)
                            {
                                string loc = certitem.GetAttribute("src");
                                string over_ride = certitem.GetAttribute("overridePins");

                                if (loc.Contains("@raw/"))
                                {
                                    finds.Add(new NetworkSecurityDto()
                                    {
                                        Description = $"Base config is configured to trust bundled certs {loc}.",
                                        Scope = "['*']",
                                        Severity = "INFO"
                                    });
                                }
                                else if (loc == "system")
                                {
                                    finds.Add(new NetworkSecurityDto()
                                    {
                                        Description = $"Base config is configured to trust  system certificates.",
                                        Scope = "['*']",
                                        Severity = "WARNING"
                                    });
                                }
                                else if (loc == "user")
                                {
                                    finds.Add(new NetworkSecurityDto()
                                    {
                                        Description = $"Base config is configured to trust user installed certificates.",
                                        Scope = "['*']",
                                        Severity = "WARNING"
                                    });
                                }
                                if (over_ride == "true")
                                {
                                    finds.Add(new NetworkSecurityDto()
                                    {
                                        Description = $"Base config is configured to bypass certificate pinning.",
                                        Scope = "['*']",
                                        Severity = "HIGH"
                                    });
                                }

                            }
                        }
                    }
                    catch (Exception)
                    {

                    }

                    try
                    {
                        XmlNodeList pinsets = cfg.GetElementsByTagName("pin-set");
                        foreach (XmlElement pinset in pinsets)
                        {
                            string exp = pinset.GetAttribute("expiration");
                            XmlNodeList pins = pinset.GetElementsByTagName("pin");
                            List<string> all_pins = new List<string>();
                            foreach (XmlElement pin in pins)
                            {
                                string digest = pinset.GetAttribute("digest");
                                string pin_val = pin?.FirstChild?.Value;
                                string tmp = string.Empty;
                                if (!string.IsNullOrEmpty(digest))
                                {
                                    tmp = $"Pin: {pin_val} Digest: {digest}";
                                }
                                else
                                {
                                    tmp = $"Pin: {pin_val}";
                                }
                                all_pins.Add(tmp);
                            }

                            if(exp != null)
                            {
                                finds.Add(new NetworkSecurityDto()
                                {
                                    Description = $"Certificate pinning expires on {exp}. After this date pinning will be disabled. ",
                                    Scope = string.Join(",", domain_list.ToArray()),
                                    Severity = "INFO"
                                });
                            }
                            else
                            {
                                finds.Add(new NetworkSecurityDto()
                                {
                                    Description = $"Certificate pinning does not have an expiry. Ensure that pins are updated before certificate expire. ",
                                    Scope = string.Join(",", domain_list.ToArray()),
                                    Severity = "SECURE"
                                });
                            }
                        }
                    }
                    catch (Exception)
                    {
                         
                    }
                }
            }
            catch (Exception ex)
            {

            }
            return finds;
        }
    }
}
