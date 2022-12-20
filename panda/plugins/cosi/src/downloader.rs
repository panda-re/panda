//use std::io::{stdout, Write, BufReader};
use std::io::Write;
use std::fs::File;
//use std::env;
use curl::easy::Easy;

pub fn download_symbol_table(file: &str, kernel: &str) -> bool {
    let mut f = File::create(file).expect("Could not create file");
    let mut buf = Vec::new();
    let mut easy = Easy::new();
    let url = "https://panda.re/volatility3_profiles/".to_owned() + kernel + ".json.xz";
	println!("Grabbing file from: {}", url);
    easy.url(&url).unwrap();
    easy
    .transfer()
    .write_function(|data| { 
        buf
        .extend_from_slice(data);
        Ok(data.len())
    })
    .unwrap();
    match easy.perform().ok() {
        Some(res) => {
            if buf.len() > 0 {
                f.write(b"\n");
                f.write_all(&buf);
                f.write(b"\n");
                println!("OK");
            } else {
				println!("Read 0x{:x} bytes into buffer", buf.len());
                println!("FAIL: could not read {} from server", kernel);
            }
        },
        None => println!("FAIL: error"),
    };
    return true;
}

/*
int download_kernelinfo(const char *file, const char *group){
	// we'll create a file, but we won't make one without a filename
	if  (file == NULL)
		return -1;
	std::cout << "Attempting to download kernelinfo.conf from panda-re.mit.edu... ";
	CURL *curl;
	CURLcode res;
	std::string url = "https://panda-re.mit.edu/kernelinfos/";
	url.append(group);
	url.append(".conf");
	std::string readBuffer;

	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		if (readBuffer.length() > 0 && res == CURLE_OK){
	  		std::ofstream kernelinfo_file;
	  		kernelinfo_file.open (file, std::ifstream::app);
	  		kernelinfo_file << "\n" << readBuffer << std::endl;
	  		kernelinfo_file.close();
        std::cout << " OK" << std::endl;
	  		return 0;
		}else if(res == CURLE_HTTP_RETURNED_ERROR) {
			std::cout << " FAIL: config not found on server" << std::endl;
    }else{
			std::cout << " FAIL: error" << std::endl;
		}
	}
	return -1;
} 
*/