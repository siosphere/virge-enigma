<?php
namespace Virge;

use Virge\Core\Config;

/**
 * Used to encrypt/decrypt data
 * @author Michael Kramer
 */
class Enigma {
    
    /**
     * Encrypt data
     * @param string $data
     * @param string $key
     * @return string
     */
    public static function encrypt($data, $key = false){
        if(!$key){
            $key = Config::get('app', 'encryption_key');
        }
        $hash = hash('sha256', $key, true);
        $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC); 
        
        $input = self::pkcs5Pad($data, $size); 

        $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, ''); 
        $iv = '0000000000000000'; 
        mcrypt_generic_init($td, $hash, $iv); 
        $encrypted = mcrypt_generic($td, $input); 
        mcrypt_generic_deinit($td); 
        mcrypt_module_close($td); 
        
        return bin2hex($encrypted); 
    }
    
    /**
     * Decrypt our data
     * @param string $data
     * @param string $key
     * @return string
     */
    public static function decrypt($data, $key = false){
        if(!$key){
            $key = Config::get('app', 'encryption_key');
        }
        $hash = hash('sha256', $key, true);
        $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC); 
        
        $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, ''); 
        $iv = '0000000000000000'; 
        mcrypt_generic_init($td, $hash, $iv);
        $decrypted = mdecrypt_generic($td, hex2bin($data)); 
        mcrypt_generic_deinit($td); 
        mcrypt_module_close($td); 
        
        return self::pkcs5Unpad($decrypted);
    }
    
    /**
     * Pack empty spaces on key
     * @param string $text
     * @param int $blocksize
     * @return string
     */
    protected static function pkcs5Pad ($text, $blocksize) { 
        $pad = $blocksize - (strlen($text) % $blocksize); 
        return $text . str_repeat(chr($pad), $pad); 
    } 

    /**
     * Unpad our text
     * @param string $text
     * @return boolean
     */
    protected static function pkcs5Unpad($text) { 
        $pad = ord($text{strlen($text)-1}); 
        
        if ($pad > strlen($text)) {
            return false;
        }
        
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) {
            return false;
        }
        
        return substr($text, 0, -1 * $pad); 
    }
    
    /**
     * Quick hashing algorithm
     * @param string $string
     * @param string $salt
     * @return string
     */
    public static function hash($string = '', $salt = ''){
        if(strlen($string) === ''){
            $string = md5(microtime());
        }
        
        $string .= $salt;
        
        return hash_hmac(Config::get('app', 'encryption_algorithm'), $string, Config::get('app', 'encryption_key'));
    }
}