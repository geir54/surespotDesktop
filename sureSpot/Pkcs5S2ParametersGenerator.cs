using System;
/*
The Bouncy Castle License
Copyright (c) 2000-2011 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sub license, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE. */

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

// Original does not support sha256. Rewritten for this project

namespace WindowsFormsApplication1
{
	/**
	* Generator for Pbe derived keys and ivs as defined by Pkcs 5 V2.0 Scheme 2.
	* This generator uses a SHA-1 HMac as the calculation function.
	* <p>
	* The document this implementation is based on can be found at
	* <a href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html">
	* RSA's Pkcs5 Page</a></p>
	*/
	public class Pkcs5S2ParametersGenerator
		: PbeParametersGenerator
	{
		private readonly IMac hMac = new HMac(new Sha256Digest());

		/**
		* construct a Pkcs5 Scheme 2 Parameters generator.
		*/
		public Pkcs5S2ParametersGenerator()
		{
		}

		private void F(
			byte[]  P,
			byte[]  S,
			int     c,
			byte[]  iBuf,
			byte[]  outBytes,
			int     outOff)
		{
			byte[]              state = new byte[hMac.GetMacSize()];
			ICipherParameters    param = new KeyParameter(P);

			hMac.Init(param);

			if (S != null)
			{
				hMac.BlockUpdate(S, 0, S.Length);
			}

			hMac.BlockUpdate(iBuf, 0, iBuf.Length);

			hMac.DoFinal(state, 0);

			Array.Copy(state, 0, outBytes, outOff, state.Length);

			for (int count = 1; count != c; count++)
			{
				hMac.Init(param);
				hMac.BlockUpdate(state, 0, state.Length);
				hMac.DoFinal(state, 0);

				for (int j = 0; j != state.Length; j++)
				{
					outBytes[outOff + j] ^= state[j];
				}
			}
		}

		private void IntToOctet(
			byte[]  Buffer,
			int     i)
		{
			Buffer[0] = (byte)((uint) i >> 24);
			Buffer[1] = (byte)((uint) i >> 16);
			Buffer[2] = (byte)((uint) i >> 8);
			Buffer[3] = (byte)i;
		}

		private byte[] GenerateDerivedKey(
			int dkLen)
		{
			int     hLen = hMac.GetMacSize();
			int     l = (dkLen + hLen - 1) / hLen;
			byte[]  iBuf = new byte[4];
			byte[]  outBytes = new byte[l * hLen];

			for (int i = 1; i <= l; i++)
			{
				IntToOctet(iBuf, i);

				F(mPassword, mSalt, mIterationCount, iBuf, outBytes, (i - 1) * hLen);
			}

			return outBytes;
		}

		/**
		* Generate a key parameter derived from the password, salt, and iteration
		* count we are currently initialised with.
		*
		* @param keySize the size of the key we want (in bits)
		* @return a KeyParameter object.
		*/
		[Obsolete("Use version with 'algorithm' parameter")]
		public override ICipherParameters GenerateDerivedParameters(
			int keySize)
		{
			return GenerateDerivedMacParameters(keySize);
		}

		public override ICipherParameters GenerateDerivedParameters(
			string	algorithm,
			int		keySize)
		{
			keySize /= 8;

			byte[] dKey = GenerateDerivedKey(keySize);

			return ParameterUtilities.CreateKeyParameter(algorithm, dKey, 0, keySize);
		}

		/**
		* Generate a key with initialisation vector parameter derived from
		* the password, salt, and iteration count we are currently initialised
		* with.
		*
		* @param keySize the size of the key we want (in bits)
		* @param ivSize the size of the iv we want (in bits)
		* @return a ParametersWithIV object.
		*/
		[Obsolete("Use version with 'algorithm' parameter")]
		public override ICipherParameters GenerateDerivedParameters(
			int	keySize,
			int	ivSize)
		{
			keySize /= 8;
			ivSize /= 8;

			byte[] dKey = GenerateDerivedKey(keySize + ivSize);

			return new ParametersWithIV(new KeyParameter(dKey, 0, keySize), dKey, keySize, ivSize);
		}

		public override ICipherParameters GenerateDerivedParameters(
			string	algorithm,
			int		keySize,
			int		ivSize)
		{
			keySize /= 8;
			ivSize /= 8;

			byte[] dKey = GenerateDerivedKey(keySize + ivSize);
			KeyParameter key = ParameterUtilities.CreateKeyParameter(algorithm, dKey, 0, keySize);

			return new ParametersWithIV(key, dKey, keySize, ivSize);
		}

		/**
		* Generate a key parameter for use with a MAC derived from the password,
		* salt, and iteration count we are currently initialised with.
		*
		* @param keySize the size of the key we want (in bits)
		* @return a KeyParameter object.
		*/
		public override ICipherParameters GenerateDerivedMacParameters(
			int keySize)
		{
			keySize /= 8;

			byte[] dKey = GenerateDerivedKey(keySize);

			return new KeyParameter(dKey, 0, keySize);
		}
	}
}
