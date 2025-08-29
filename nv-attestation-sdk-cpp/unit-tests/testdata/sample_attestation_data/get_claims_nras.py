#!/usr/bin/env python3

import argparse
import base64
import json
import requests
import sys
from pathlib import Path


def hex_to_binary_bytes(hex_string):
    """Convert hex string to binary bytes."""
    try:
        # Remove any whitespace and newlines
        hex_string = hex_string.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        # Convert hex string to bytes
        return bytes.fromhex(hex_string)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {e}")


def encode_binary_to_base64(binary_data):
    """Encode binary data to base64 string."""
    return base64.b64encode(binary_data).decode('utf-8')


def read_hex_file_and_encode(file_path):
    """Read a hex file, convert to binary bytes, and return base64 encoded content."""
    try:
        with open(file_path, 'r') as f:
            hex_content = f.read()
            binary_data = hex_to_binary_bytes(hex_content)
            return encode_binary_to_base64(binary_data)
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading hex file {file_path}: {e}")
        sys.exit(1)


def read_and_encode_file(file_path):
    """Read a file and return its base64 encoded content."""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            return base64.b64encode(content).decode('utf-8')
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)


def decode_jwt_payload(jwt_token):
    """Decode JWT payload (middle part) from a JWT token."""
    try:
        # JWT tokens have 3 parts separated by dots: header.payload.signature
        parts = jwt_token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        # Get the payload (middle part) and add padding if needed
        payload_b64 = parts[1]
        # Add padding if needed (base64 requires length to be multiple of 4)
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        
        # Decode base64 and parse JSON
        payload_bytes = base64.b64decode(payload_b64)
        payload_json = json.loads(payload_bytes.decode('utf-8'))
        
        return payload_json
    except Exception as e:
        print(f"Error decoding JWT payload: {e}")
        return None


def save_detached_eat_response(response_data, output_path):
    """Save the detached EAT response to two files: original and decoded."""
    try:
        output_path = Path(output_path)
        base_name = output_path.stem
        base_dir = output_path.parent
        
        # Save original response as _detached_eat.json
        detached_eat_path = base_dir / f"{base_name}_detached_eat.json"
        with open(detached_eat_path, 'w') as f:
            json.dump(response_data, f, indent=2)
        print(f"Original response saved to: {detached_eat_path}")
        
        # Parse the detached EAT format: [["JWT", "signed_data"], {"GPU-0": jwt-encoded-data}]
        if isinstance(response_data, list) and len(response_data) == 2:
            # Extract the JWT data from the second element
            jwt_data = response_data[1]
            if isinstance(jwt_data, dict):
                decoded_data = {}
                for key, jwt_token in jwt_data.items():
                    if isinstance(jwt_token, str) and '.' in jwt_token:
                        # Decode the JWT payload
                        decoded_payload = decode_jwt_payload(jwt_token)
                        if decoded_payload is not None:
                            decoded_data[key] = decoded_payload
                            print(f"Successfully decoded JWT for {key}")
                        else:
                            print(f"Failed to decode JWT for {key}")
                    else:
                        print(f"Skipping non-JWT data for {key}")
                
                # Save decoded data as _decoded.json
                decoded_path = base_dir / f"{base_name}_decoded.json"
                with open(decoded_path, 'w') as f:
                    json.dump(decoded_data, f, indent=2)
                print(f"Decoded JWT payloads saved to: {decoded_path}")
            else:
                print("Warning: Second element of response is not a dictionary")
        else:
            print("Warning: Response format doesn't match expected detached EAT format")
            
    except Exception as e:
        print(f"Error saving detached EAT response: {e}")


def make_attestation_request(attestation_report_path, cert_chain_path, output_path, device_type):
    """Make POST request to NVIDIA attestation service."""
    
    # Hardcoded values as specified
    NONCE = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
    CLAIMS_VERSION = "3.0"
    
    # Select URL based on device type
    if device_type == "switch":
        URL = "https://nras.attestation-stg.nvidia.com/v4/attest/switch"
        ARCH = "LS10"
    else:  # gpu
        ARCH = "HOPPER"
        URL = "https://nras.attestation.nvidia.com/v4/attest/gpu"
    
    # Read and encode the files
    print(f"Reading attestation report from: {attestation_report_path}")
    evidence_b64 = read_hex_file_and_encode(attestation_report_path)
    
    print(f"Reading certificate chain from: {cert_chain_path}")
    cert_chain_b64 = read_and_encode_file(cert_chain_path)
    
    # Construct the request payload
    payload = {
        "nonce": NONCE,
        "arch": ARCH,
        "claims_version": CLAIMS_VERSION,
        "evidence_list": [
            {
                "evidence": evidence_b64,
                "certificate": cert_chain_b64
            }
        ]
    }
    
    # Make the POST request
    print(f"Making POST request to {device_type.upper()} attestation service: {URL}")
    try:
        headers = {
            'Content-Type': 'application/json'
        }
        
        response = requests.post(URL, json=payload, headers=headers, timeout=30)
        
        print(f"Response status code: {response.status_code}")
        
        # Print request ID from response headers if available
        request_id = response.headers.get('x-request-id') or response.headers.get('request-id') or response.headers.get('X-Request-ID')
        if request_id:
            print(f"Request ID: {request_id}")
        else:
            print("Request ID not found in response headers")
        
        # Ensure output directory exists
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if response.status_code == 200:
            print("Attestation request successful!")
            
            # Parse and save the detached EAT response
            if response.headers.get('content-type', '').startswith('application/json'):
                response_data = response.json()
                save_detached_eat_response(response_data, output_path)
            else:
                print("Warning: Response is not JSON format")
                # Save raw response text to original output file
                with open(output_path, 'w') as f:
                    f.write(response.text)
                print(f"Raw response saved to: {output_path}")
        else:
            print(f"Attestation request failed with status {response.status_code}")
            if response.text:
                print(f"Error response: {response.text}")
                # Save error response
                with open(output_path, 'w') as f:
                    f.write(response.text)
        
        return response.status_code == 200
        
    except requests.exceptions.RequestException as e:
        print(f"Error making HTTP request: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Make POST request to NVIDIA attestation service for GPU or Switch evidence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python3 get_claims_nras.py --device gpu --attestation-report /path/to/attestation_report.bin --cert-chain /path/to/cert_chain.pem output_base_name
  python3 get_claims_nras.py --device switch --attestation-report /path/to/switch_report.bin --cert-chain /path/to/cert_chain.pem output_base_name

The output file name will be used as a base to save:
  - {output_base_name}_detached_eat.json (original response)
  - {output_base_name}_decoded.json (decoded JWT payloads)
        """
    )

    parser.add_argument(
        '--device',
        choices=['gpu', 'switch'],
        required=True,
        help='Device type for attestation (gpu or switch)'
    )
    
    parser.add_argument(
        '--attestation-report',
        required=True,
        help='Path to the attestation report file'
    )
    
    parser.add_argument(
        '--cert-chain',
        required=True,
        help='Path to the certificate chain file'
    )
    
    parser.add_argument(
        'output_base_name',
        help='Base name for output files (will be used to create _detached_eat.json and _decoded.json files)'
    )
    
    args = parser.parse_args()
    
    # Validate input files exist
    if not Path(args.attestation_report).exists():
        print(f"Error: Attestation report file does not exist: {args.attestation_report}")
        sys.exit(1)
    
    if not Path(args.cert_chain).exists():
        print(f"Error: Certificate chain file does not exist: {args.cert_chain}")
        sys.exit(1)
    
    # Make the attestation request
    success = make_attestation_request(args.attestation_report, args.cert_chain, args.output_base_name, args.device)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main() 