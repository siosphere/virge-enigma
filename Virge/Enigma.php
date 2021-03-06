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
    public static function encrypt($data, $key = false, $encryptionAlgorithm = MCRYPT_RIJNDAEL_128){
        if(!$key){
            $key = Config::get('app', 'encryption_key');
        }
        $hash = hash('sha256', $key, true);
        $size = mcrypt_get_block_size($encryptionAlgorithm, MCRYPT_MODE_CBC); 
        
        $input = self::pkcs5Pad($data, $size); 

        $td = mcrypt_module_open($encryptionAlgorithm, '', MCRYPT_MODE_CBC, ''); 
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
    public static function decrypt($data, $key = false, $encryptionAlgorithm = MCRYPT_RIJNDAEL_128){
        if(!$key){
            $key = Config::get('app', 'encryption_key');
        }
        $hash = hash('sha256', $key, true);
        $size = mcrypt_get_block_size($encryptionAlgorithm, MCRYPT_MODE_CBC); 
        
        $td = mcrypt_module_open($encryptionAlgorithm, '', MCRYPT_MODE_CBC, ''); 
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
     * @param string $encryptionAlgorithm
     * @param string $key
     * @return string
     */
    public static function hash($string = '', $salt = '', $encryptionAlgorithm = false, $key = false){
        if(!$encryptionAlgorithm) {
            $encryptionAlgorithm = Config::get('app', 'encryption_algorithm');
        }
        
        if(!$key){
            $key = Config::get('app', 'encryption_key');
        }
        
        if(strlen($string) === ''){
            $string = md5(microtime());
        }
        
        $string .= $salt;
        
        return hash_hmac($encryptionAlgorithm, $string, $key);
    }
    
    /**
     * Get the MD5 hash of a file
     * @param string $filePath
     * @return string
     * @throws \InvalidArgumentException
     */
    public static function md5File($filePath = '') {
        if(!is_file($filePath)) {
            throw new \InvalidArgumentException(sprintf("%s does not exists", $filePath));
        }
        
        return md5_file($filePath);
    }
    
    /**
     * Encrypt inputFile into outputFile using provided encryption key
     * @param string $inputFile
     * @param string $outputFile
     * @param string $key
     * @throws \InvalidArgumentException
     */
    public static function encryptFile($inputFile, $outputFile, $key = false, $encryptionAlgorithm = MCRYPT_RIJNDAEL_128)
    {
        
        if(!is_file($inputFile)) {
            throw new \InvalidArgumentException(sprintf("%s does not exists", $inputFile));
        }
        
        if(is_file($outputFile)) {
            throw new \InvalidArgumentException(sprintf("%s already exists", $outputFile));
        }
        $handle = fopen($inputFile, 'r');
        
        $outputHandle = fopen($outputFile, 'a');
        
        $fileSize = filesize($inputFile);
        $blockSize = 1024 * 1024; //1MB
        $totalBlocks = ceil($fileSize / $blockSize);
        $currentBlock = 0;
        while($currentBlock < $totalBlocks) {
            fseek($handle, $currentBlock * $blockSize);
            $contents = bin2hex(fread($handle, $blockSize));
            $encryptedContents = self::encrypt($contents, $key, $encryptionAlgorithm) . "\n";
            fwrite($outputHandle, $encryptedContents);
            $currentBlock++;
        }
        fclose($handle);
        fclose($outputHandle);
    }
    
    /**
     * Decrypt inputFile into outputFile using provided encryption key
     * @param string $inputFile
     * @param string $outputFile
     * @param string $key
     * @throws \InvalidArgumentException
     */
    public static function decryptFile($inputFile, $outputFile, $key = false, $encryptionAlgorithm = MCRYPT_RIJNDAEL_128)
    {
        if(!is_file($inputFile)) {
            throw new \InvalidArgumentException(sprintf("%s does not exists", $inputFile));
        }
        
        if(is_file($outputFile)) {
            throw new \InvalidArgumentException(sprintf("%s already exists", $outputFile));
        }
        
        $file = new \SplFileObject($inputFile);
        
        $outputHandle = fopen($outputFile, 'a');
        
        while (!$file->eof()) {
            $line = trim($file->current(), "\n");
            if(strlen($line) > 0 ){
                $decryptedContents = hex2bin(self::decrypt($line, $key, $encryptionAlgorithm));
                fwrite($outputHandle, $decryptedContents);
            }
            $file->next();
            
        }
        $file = null;
        fclose($outputHandle);
    }
}