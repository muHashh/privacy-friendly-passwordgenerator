/**
 * This file is part of Privacy Friendly Password Generator.

 Privacy Friendly Password Generator is free software:
 you can redistribute it and/or modify it under the terms of the
 GNU General Public License as published by the Free Software Foundation,
 either version 3 of the License, or any later version.

 Privacy Friendly Password Generator is distributed in the hope
 that it will be useful, but WITHOUT ANY WARRANTY; without even
 the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 See the GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Privacy Friendly Password Generator. If not, see <http://www.gnu.org/licenses/>.
 */

package org.secuso.privacyfriendlypasswordgenerator.generator;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This class handles the hashing and the creation of passwords. Please initialize first.
 * Do not forget to hash at least once with PBKDF2 because otherwise the password might look not very
 * random. It is safe to hash often because an attacker has to hash as often as you did for
 * every try of a brute-force attack. getPassword creates a password string out of the hash
 * digest.
 * <p>
 * Basic class structure and idea taken from https://github.com/pinae/ctSESAM-android/
 * last access 1st November 2016
 * Added the BCrypt component and ShuffleString
 *
 * @author Karola Marky
 * @version 20180112
 */
public class PasswordGenerator {

    private byte[] hashValue;

    public PasswordGenerator(String domain,
                             String username,
                             String masterpassword,
                             String deviceID,
                             int iteration,
                             int hashIterations,
                             String hashAlgorithm) {

        String temp = Base64.encode_base64(
                PBKDF2.hmac(
                        hashAlgorithm,
                        UTF8.encode(masterpassword),
                        UTF8.encode(String.valueOf(iteration * 100) + domain + username + deviceID),
                        hashIterations),
                22);

        this.hashValue = transformPassword(BCrypt.hashpw(masterpassword, "$2a$10$" + temp));
    }

    //cuts the salt from the password
    private byte[] transformPassword(String password) {
        byte[] passwordChar = UTF8.encode(password);
        byte[] transformedPassword = new byte[31];


        for (int i = 29; i < passwordChar.length; i++) {
            transformedPassword[i - 29] = passwordChar[i];
        }

        return transformedPassword;

    }

    public String getPassword(int specialCharacters, int lowerCaseLetters, int upperCaseLetters,
                              int numbers, int length) {

        length /= 2;

        byte[] positiveHashValue = new byte[hashValue.length + 1];
        positiveHashValue[0] = 0;
        System.arraycopy(hashValue, 0, positiveHashValue, 1, hashValue.length);
        BigInteger hashNumber = new BigInteger(positiveHashValue);
        Clearer.zero(positiveHashValue);
        String password = "";

        List<String> wordSet = new ArrayList<>(Arrays.asList("The","Of","And","A","To","In","Is",
                                                            "You","That","It","He","Was","For","On",
                                                            "Are","As","With","His","They","I","At",
                                                            "Be","This","Have","From","Or","One","Had",
                                                            "By","Word","But","Not","What","All","Were",
                                                            "We","When","Your","Can","Said","There",
                                                            "Use","An","Each","Which","She","Do","How",
                                                            "Their","If","Will","Up","Other","About",
                                                            "Out","Many","Then","Them","These","So",
                                                            "Some","Her","Would","Make","Like","Him",
                                                            "Into","Time","Has","Look","Two","More",
                                                            "Write","Go","See","Number","No","Way",
                                                            "Could","People","My","Than","First",
                                                            "Water","Been","Call","Who","Oil","Its",
                                                            "Now","Find","Long","Down","Day","Did",
                                                            "Get","Come","Made","May","Part"));

        if (wordSet.size() > 0) {
            String template = shuffleTemplate(TemplateFactory.createTemplateFromParameters(specialCharacters, lowerCaseLetters, upperCaseLetters,
            numbers, length));

            if (wordSet.size() > 0) {
                for (int i = 0; i < template.length(); i++) {
                    if (hashNumber.compareTo(BigInteger.ZERO) > 0) {
                        BigInteger setSize = BigInteger.valueOf(wordSet.size());
                        BigInteger[] divAndMod = hashNumber.divideAndRemainder(setSize);
                        hashNumber = divAndMod[0];
                        int mod = divAndMod[1].intValue();
                        password += wordSet.get(mod);
                    }
                }
            }

        }
        return password;
    }

    
    private String shuffleTemplate(String s){

        BigInteger bigInt = new BigInteger(hashValue);

        int index;
        char temp;
        char[] array = s.toCharArray();
        for (int i = array.length - 1; i > 0; i--)
        {
            BigInteger tempInt = BigInteger.valueOf(i);
            BigInteger[] divAndMod = bigInt.divideAndRemainder(tempInt);
            bigInt = divAndMod[0];
            index = divAndMod[1].intValue();
            temp = array[index];
            array[index] = array[i];
            array[i] = temp;
        }
        return String.valueOf(array);
    }


    protected void deleteFinalize() throws Throwable {
        Clearer.zero(this.hashValue);
        super.finalize();
    }
}