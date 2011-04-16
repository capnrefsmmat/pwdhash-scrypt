/*
 * JavaScript implementation of Password-Based Key Derivation Function 2
 * (PBKDF2) as defined in RFC 2898.
 *
 * Derived from Parvez Anandam's implementation,
 * Version 1.1 
 * Copyright (c) 2007, Parvez Anandam
 * parvez.anandam@cern.ch
 * http://anandam.name/pbkdf2
 *
 * Distributed under the BSD license
 *
 * (Uses Paul Johnston's excellent SHA-1 JavaScript library sha1.js)
 * Thanks to Felix Gartsman for pointing out a bug in version 1.0
 */


/*
 * The four arguments to the constructor of the PBKDF2 object are 
 * the password, salt, number of iterations and number of bytes in
 * generated key. This follows the RFC 2898 definition: PBKDF2 (P, S, c, dkLen)
 *
 * The method deriveKey takes two parameters, both callback functions:
 * the first is used to provide status on the computation, the second
 * is called with the result of the computation (the generated key in hex).
 *
 * Example of use:
 *
 *    <script src="sha1.js"></script>
 *    <script src="pbkdf2.js"></script>
 *    <script>
 *    var mypbkdf2 = new PBKDF2("mypassword", "saltines", 1000, 16);
 *    var status_callback = function(percent_done) {
 *        document.getElementById("status").innerHTML = "Computed " + percent_done + "%"};
 *    var result_callback = function(key) {
 *        document.getElementById("status").innerHTML = "The derived key is: " + key};
 *    mypbkdf2.deriveKey(status_callback, result_callback);
 *    </script>
 *    <div id="status"></div>
 *
 */

function PBKDF2(password, salt, num_iterations, num_bytes)
{
	// Remember the password and salt
	var m_bpassword = rstr2binb(password);
	var m_salt = salt;

	// Total number of iterations
	var m_total_iterations = num_iterations;

	// Run iterations in chunks instead of all at once, so as to not block.
	// Define size of chunk here; adjust for slower or faster machines if necessary.
	var m_iterations_in_chunk = 10;

	// Iteration counter
	var m_iterations_done = 0;

	// Key length, as number of bytes
	var m_key_length = num_bytes;

	// The length (number of bytes) of the output of the pseudo-random function.
	// Since HMAC-SHA256 is used here, it's 32 bytes.
	var m_hash_length = 32;

	// Number of hash-sized blocks in the derived key (called 'l' in RFC2898)
	var m_total_blocks = Math.ceil(m_key_length/m_hash_length);

	// Start computation with the first block
	var m_current_block = 1;

	// Used in the HMAC-SHA256 computations
	var m_ipad = new Array(16);
	var m_opad = new Array(16);

	// This is where the result of the iterations gets sotred
	var m_buffer = new Array(0x0,0x0,0x0,0x0,0x0);
	
	// The result
	var m_key = "";

	// The function to call with the result
	var m_result_func;

	// The function to call with status after computing every chunk
	var m_status_func;

	// Set up the HMAC-SHA256 computations
	if (m_bpassword.length > 16) m_bpassword = binb_sha256(m_bpassword, password.length * chrsz);
	for(var i = 0; i < 16; ++i)
	{
		m_ipad[i] = m_bpassword[i] ^ 0x36363636;
		m_opad[i] = m_bpassword[i] ^ 0x5C5C5C5C;
	}


	// Starts the computation
	this.deriveKey = function(status_callback, result_callback)
	{
		m_status_func = status_callback;
		m_result_func = result_callback;
		var this_object = this;
		setTimeout(function() { this_object.do_PBKDF2_iterations() }, 0);
	}


	// The workhorse
	this.do_PBKDF2_iterations = function()
	{
		var iterations = m_iterations_in_chunk;
		if (m_total_iterations - m_iterations_done < m_iterations_in_chunk)
			iterations = m_total_iterations - m_iterations_done;
			
		for(var i=0; i<iterations; ++i)
		{
			// compute HMAC-256 
			if (m_iterations_done == 0)
			{
				var salt_block = m_salt +
						String.fromCharCode(m_current_block >> 24 & 0xF) +
						String.fromCharCode(m_current_block >> 16 & 0xF) +
						String.fromCharCode(m_current_block >>  8 & 0xF) +
						String.fromCharCode(m_current_block       & 0xF);

				m_hash = binb_sha256(m_ipad.concat(rstr2binb(salt_block)),
								   512 + salt_block.length * 8);
				m_hash = binb_sha256(m_opad.concat(m_hash), 512 + 160);
			}
			else
			{
				m_hash = binb_sha256(m_ipad.concat(m_hash), 
								   512 + m_hash.length * 32);
				m_hash = binb_sha256(m_opad.concat(m_hash), 512 + 160);
			}

        	for(var j=0; j<m_hash.length; ++j)
                	m_buffer[j] ^= m_hash[j];

			m_iterations_done++;
		}

		// Call the status callback function
		m_status_func( (m_current_block - 1 + m_iterations_done/m_total_iterations) / m_total_blocks * 100);

		if (m_iterations_done < m_total_iterations)
		{
			var this_object = this;
			setTimeout(function() { this_object.do_PBKDF2_iterations() }, 0);
		}
		else
		{
			if (m_current_block < m_total_blocks)
			{
				// Compute the next block (T_i in RFC 2898)
				
				m_key += binb2hex(m_buffer);
			
				m_current_block++;
				m_buffer = new Array(0x0,0x0,0x0,0x0,0x0);
				m_iterations_done = 0;

				var this_object = this;
				setTimeout(function() { this_object.do_PBKDF2_iterations() }, 0);
			}
			else
			{
				// We've computed the final block T_l; we're done.
			
				var tmp = rstr2hex(binb2rstr(m_buffer));
				m_key += tmp.substr(0, (m_key_length - (m_total_blocks - 1) * m_hash_length) * 2 );
				
				// Call the result callback function
				m_result_func(m_key);
			}
		}
	}
}
