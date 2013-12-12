using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace WindowsFormsApplication1
{
    class SurespotIdentity
    {
        private String mUsername;
        private String mLatestVersion;
        private String mSalt;

        private Dictionary<string, string> mKeyPairs;// = new Dictionary<string, string>();

        public SurespotIdentity(String username, String salt)
        {
            this.mUsername = username;
            mSalt = salt;
        }

        public String getUsername()
        {
            return mUsername;
        }

        public String getSalt()
        {
            return mSalt;
        }

    }
}
