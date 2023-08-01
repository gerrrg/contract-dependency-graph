import json
import sys
import os
import binascii

import balpy
from multicaller import multicaller

import networkx as nx
import matplotlib.pyplot as plt

from ens import ENS

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
ZERO_BYTES = "0x0000000000000000000000000000000000000000000000000000000000000000";

class Suppressor(object):
    def __enter__(self):
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self
    def __exit__(self, type, value, traceback):
        sys.stdout = self.stdout
        sys.stderr = self.stderr
        if type is not None:
            a=0;
            # Do normal exception handling
    def write(self, x): pass

def checksum(bal, address):
	return(bal.web3.toChecksumAddress(address));

def bytesToString(as_bytes):
	as_hex = binascii.hexlify(as_bytes);
	as_string = "0x" + as_hex.decode("ascii");
	return(as_string);

def bytes32ToAddress(bytes_data):
	return("0x" + bytes_data[-40:]);

def etherscanApiUrlGetAbi(bal, address):
	url_string = "/api?module=contract&action=getabi&address={}&apikey=".format(address);
	return(etherscanApiUrl(bal, address, url_string));

def etherscanApiUrlGetSourceCode(bal, address):
	url_string = "/api?module=contract&action=getsourcecode&address={}&apikey=".format(address);
	return(etherscanApiUrl(bal, address, url_string));

def etherscanApiUrl(bal, address, url_string):
	success = False;
	results = None;
	max_retries = 3;
	tries = 0;
	while not success and tries < max_retries:
		tries += 1;
		try:
			response = bal.callEtherscan(url_string);
			status = response["status"];
			if status == "1":
				results = response["result"];
				if isinstance(results, str):
					results = json.loads(results);
					success = True;
		except KeyboardInterrupt:
			print("Caught Ctrl+C");
			quit();
		except Exception as e:
			print(e);
			print("Attempt", tries, "of", max_retries, "for", address)
	return(results);


def getStorageAtSlot(w3, contract, slot):
	data = w3.toHex(
		w3.eth.get_storage_at(
			w3.toChecksumAddress(contract),
			slot,
		)
	);
	return(data);

def findAddressesGenericContract(mc, contract, abi):
		addresses = [];
		fn_names = [];

		for fn in abi:
			if fn["type"] == "constructor" or not "inputs" in fn:
				continue;
			elif fn["inputs"] == [] and fn["type"] == "function":
				for output in fn["outputs"]:
					if "address" in output["type"]:
						mc.addCall(contract, abi, fn["name"]);
						fn_names.append(fn["name"]);
		try:
			outputData = mc.execute();
		except:
			outputData = ([],[False]);
		for outputs, success in zip(outputData[0], outputData[1]):
			if success:
				for element in outputs:
					addresses.append(element);

		filtered_addresses = [];
		filtered_fn_names = [];

		for a, n in zip(addresses, fn_names):
			if not a == ZERO_ADDRESS and len(a) > 0:
				filtered_addresses.append(a);
				filtered_fn_names.append(n);

		num_addresses = len(filtered_addresses);
		if num_addresses > 0:
			print("\tFound", num_addresses, "address dependencies:");
			for address in filtered_addresses:
				print("\t\t" + address);
		return(filtered_addresses, filtered_fn_names);

def findHardCodedAddresses(source_code):
	addresses = [];
	names = [];

	for c in source_code:
		code = c["SourceCode"];
		sources = {};

		try:
			sources = json.loads(code[1:-1])["sources"]; #need to remove leading/trailing '{', '}'
		except:
			sources[0] = {"content":code};

		for key in sources:
			source = sources[key]["content"];
			for line in source.splitlines():
				if "address" in line and "constant" in line:

					# get const address
					elements = line.split(";")
					address = elements[0].split()[-1];

					# check for things like address(0x1)
					if not address[:2] == "0x":
						continue;

					# get name of const address
					elements = line.split("=")
					name = elements[0].strip().split()[-1];

					addresses.append(address);
					names.append(name);
	if len(names) > 0:
		print("\tFound", len(names), "hardcoded addresses:")
		for a,n in zip(addresses,names):
			print("\t\t" + n, a)

	return(addresses, names);

def findHardCodedRoles(source_code):
	names = [];
	for c in source_code:
		code = c["SourceCode"];
		sources = {};
		try:
			sources = json.loads(code[1:-1])["sources"]; #need to remove leading/trailing '{', '}'
		except:
			sources[0] = {"content":code};

		for key in sources:
			source = sources[key]["content"];
			for line in source.splitlines():
				if "bytes" in line and "constant" in line and "_ROLE" in line and "keccak" in line and not "MY_ROLE" in line:
					# get name of ROLEs
					elements = line.split("=")
					name = elements[0].strip().split()[-1];
					names.append(name);
	if len(names) > 0:
		print("\tFound", len(names), "hardcoded ROLEs:")
		for n in names:
			print("\t\t" + n)

	return(names);

def generateEventTopic(bal, name, inputs):
	arguments = []
	for element in inputs:
		arguments.append(element["type"]);
	abiBrief = name + "(" + ",".join(arguments) + ")";
	eventTopic = bal.web3.sha3(text=abiBrief).hex();
	return(eventTopic);

def getAllInstancesOfEvent(bal, address, eventTopic):
	endblock = 0;
	first = True;
	retries = 0;
	maxRetries = 5;
	allTxns = [];

	while first or len(txns) > 0:
		first = False;
		retries = 0;
		while retries < maxRetries:
			retries += 1;
			try:
				txns = getTransactionsByEvent(bal, address, eventTopic, startblock=endblock+1);
				break;
			except KeyboardInterrupt:
				print("Caught Ctrl+C");
				quit();
			except Exception as e:
				print(e);
				print("Retrying...");
		if len(txns) == 0:
			break;
		allTxns.extend(txns);
		for txn in txns:
			endblock = int(txn["blockNumber"], 16);
	return allTxns;

def getTransactionsByEvent(bal, address, topic, startblock=0, endblock="latest", verbose=False):
	if verbose:
		print("\tQuerying data after block", startblock);
	
	url = "/api?module=logs&action=getLogs&fromBlock={startblock}&toBlock={endblock}&address={address}&topic0={topic}&apikey=";
	urlString = url.format(startblock=startblock, endblock=endblock, address=address, topic=topic);
	txns = bal.callEtherscan(urlString, verbose=verbose);

	if int(txns["status"]) == 0:
		return([]);
	elif int(txns["status"]) == 1:
		return(txns["result"]);

def analyzeEip1967ProxyContract(bal, contract, abi):
		isProxyContract = False;
		addresses = [];
		labels = [];
		for fn in abi:
			if fn["type"] == "constructor" or not "inputs" in fn:
				continue;
			elif fn["name"] == "Upgraded" and fn["inputs"][0]["name"] == "implementation":
				isProxyContract = True;
				break;
		
		if isProxyContract:
			print("\tContract is an EIP1967 Proxy!");
			# address = asdf;
			w3 = bal.web3;
			# bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
			implementation_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
			impl_data = str(getStorageAtSlot(w3, contract, implementation_slot));
			if not impl_data == ZERO_BYTES:
				impl_address = bytes32ToAddress(impl_data);
				addresses.append(impl_address);
				labels.append("Proxy Implementation");
				print("\t\tFound Implementation:", impl_address);

			# bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)
			beacon_slot = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
			beacon_data = str(getStorageAtSlot(w3, contract, beacon_slot));
			if not beacon_data == ZERO_BYTES:
				beacon_address = bytes32ToAddress(beacon_data);
				addresses.append(beacon_address);
				labels.append("Proxy Beacon");
				print("\t\tFound Beacon:", beacon_address);

			# bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)
			admin_slot = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
			admin_data = str(getStorageAtSlot(w3, contract, admin_slot));
			if not admin_data == ZERO_BYTES:
				admin_address = bytes32ToAddress(admin_data);
				addresses.append(admin_address);
				labels.append("Proxy Admin");
				print("\t\tFound Admin:", admin_address);

		return(addresses, labels);

def analyzeGnosisSafe(bal, contract, abi):
		isProxyContract = False;
		addresses = [];
		labels = [];
		for fn in abi:
			if fn["type"] == "constructor" and len(fn["inputs"]) >= 1 and fn["inputs"][0]["name"] == "_singleton":
				isProxyContract = True;
				break;
		impl_address = None;
		if isProxyContract:
			print("\tContract is a Gnosis Safe Proxy Contract!");
			singleton_slot = 0;
			singleton_data = str(getStorageAtSlot(bal.web3, contract, singleton_slot));
			if not singleton_data == ZERO_BYTES:
				impl_address = bytes32ToAddress(singleton_data);
			print("\t\tImplementation:", impl_address);

			# Check to see if contract is a Gnosis Safe
			safe_info = getGnosisSafeOwners(bal, impl_address, contract);

			thresh = str(safe_info["threshold"]);
			num_owners = str(len(safe_info["owners"]));

			addresses.append(impl_address);
			labels.append("Safe Impl (" + thresh + " of " + num_owners + ")");

			for owner in safe_info["owners"]:
				addresses.append(owner);
				labels.append("owner");

		return(addresses, labels);

def findActiveRoles(bal, contract_address, abi, source_code):
	addresses = [];
	labels = [];

	roles = findHardCodedRoles(source_code);
	roles_by_hash = {bal.web3.sha3(text=role).hex():role for role in roles};
	if len(roles) > 0:
		events = ["RoleGranted", "RoleRevoked", "RoleAdminChanged"];
		event_data = {};
		event_abis = {e:None for e in events};
		for fn in abi:
			if "name" in fn:
				if fn["name"] in events:
					event_abis[fn["name"]] = fn["inputs"];

		for event_name in event_abis:
			event_abi = event_abis[event_name];
			topic = generateEventTopic(bal, event_name, event_abi);
			event_data[event_name] = getAllInstancesOfEvent(bal, contract_address, topic);

		event_transactions_by_block = {};
		for event_name in event_data:
			idx = 0;
			for event in event_data[event_name]:
				block = int(event["blockNumber"], 16);
				event_transactions_by_block[block] = event["transactionHash"]

		sorted_txns = list(event_transactions_by_block.keys());
		sorted_txns.sort();

		role_info = {
			"roles":{role:set() for role in roles},
			"role_admin":None
		}

		contract = bal.web3.eth.contract(address=checksum(bal, contract_address), abi=abi);

		for block in sorted_txns:
			tx_hash = event_transactions_by_block[block];
			receipt = bal.web3.eth.getTransactionReceipt(tx_hash);

			logs_by_event = {};
			with Suppressor():
				for event in events:
					logs_by_event[event] = contract.events[event]().processReceipt(receipt);

			role = "RoleGranted";
			if len(logs_by_event[role]) > 0:
				for log in logs_by_event[role]:
					account = log.args.account;
					role_string = bytesToString(log.args.role)
					try:
						role_info["roles"][roles_by_hash[role_string]].add(account);
					except Exception as e:
						print("\t\tRole not found:", role_string);
			role = "RoleRevoked";
			if len(logs_by_event[role]) > 0:
				for log in logs_by_event[role]:
					account = log.args.account;
					role_string = bytesToString(log.args.role)
					try:
						role_info["roles"][roles_by_hash[role_string]].remove(account);
					except Exception as e:
						print("\t\tRole not found:", role_string);
			'''
			role = "RoleAdminChanged";
			if len(logs_by_event[role]) > 0:
				for log in logs_by_event[role]:
					print(log)
					role_string = bytesToString(log.args.role)
					try:
						print("removing", account)
						role_info["roles"][roles_by_hash[role_string]].remove(account);
					except Exception as e:
						print(e);
						print("Role not found:", role_string);
			'''

		for r in role_info["roles"]:
			ads = list(role_info["roles"][r]);
			addresses.extend(ads);
			labels.extend([r] * len(ads));

			print("\t\tFound", len(ads), "addresses with role", r + ":");
			for a in ads:
				print("\t\t\t" + a)

	return(addresses, labels);

def getGnosisSafeOwners(bal, contract, proxy):
	abi = etherscanApiUrlGetAbi(bal, contract);
	safe = bal.web3.eth.contract(address=checksum(bal, proxy), abi=abi);

	addresses = [];
	labels = [];
	isGnosisSafe = False;

	events = ["SafeSetup","ChangedThreshold", "AddedOwner", "RemovedOwner"];
	event_data = {};
	event_abis = {e:None for e in events};
	for fn in abi:
		if "name" in fn:
			if fn["name"] == "checkNSignatures":
				isGnosisSafe = True;
			if fn["name"] in events:
				event_abis[fn["name"]] = fn["inputs"];

	if isGnosisSafe:
		for event_name in event_abis:
			event_abi = event_abis[event_name];
			topic = generateEventTopic(bal, event_name, event_abi);
			event_data[event_name] = getAllInstancesOfEvent(bal, proxy, topic);

		event_transactions_by_block = {};
		for event_name in event_data:
			idx = 0;
			for event in event_data[event_name]:
				block = int(event["blockNumber"], 16);
				event_transactions_by_block[block] = event["transactionHash"]

		sorted_txns = list(event_transactions_by_block.keys());
		sorted_txns.sort();

		safe_info = {
			"owners":set(),
			"threshold":None
		}

		for block in sorted_txns:
			tx_hash = event_transactions_by_block[block];
			receipt = bal.web3.eth.getTransactionReceipt(tx_hash);

			with Suppressor():
				logs_safe_setup = safe.events.SafeSetup().processReceipt(receipt);
				logs_change_threshold = safe.events.ChangedThreshold().processReceipt(receipt);
				logs_added_owner = safe.events.AddedOwner().processReceipt(receipt);
				logs_removed_owner = safe.events.RemovedOwner().processReceipt(receipt);

			if len(logs_safe_setup) > 0:
				for log in logs_safe_setup:
					owners = log["args"]["owners"];
					for owner in owners:
						safe_info["owners"].add(owner);
					safe_info["threshold"] = log["args"]["threshold"];

			if len(logs_change_threshold) > 0:
				for log in logs_change_threshold:
					safe_info["threshold"] = log["args"]["threshold"];
			if len(logs_added_owner) > 0:
				for log in logs_added_owner:
					safe_info["owners"].add(log["args"]["owner"]);
			if len(logs_removed_owner) > 0:
				for log in logs_removed_owner:
					safe_info["owners"].remove(log["args"]["owner"]);
	return(safe_info);

def main():
	network = "mainnet";
	verbose = False;

	customConfig = None;
	if network in ["avalanche"]:
		customConfig = os.path.join("customConfig",network + ".json");

	if not len(sys.argv) == 2:
		print("Usage: python", sys.argv[0], "<contract_address>");
		quit();

	root_contract = sys.argv[1];

	contracts = [];
	contracts.append(root_contract);
	contract_names = {};

	# Initialize graph data structure (use multigraph to get edge labels)
	G = nx.MultiGraph();
	G.add_node(root_contract);

	# initialize balpy, multicaller
	bal = balpy.balpy.balpy(network, customConfigFile=customConfig);
	mc = multicaller.multicaller(	_chainId=bal.networkParams[network]["id"],
									_web3=bal.web3,
									_maxRetries=5,
									_verbose=verbose,
									_allowFailure=True);
	ns = ENS.fromWeb3(bal.web3);

	# Iterate through all contracts
	# Note: additional contracts are added to this list as they are found
	for contract in contracts:
		print("Investigating address:", contract);
		addresses = [];
		labels = [];
		
		is_eoa = len(bal.web3.eth.get_code(checksum(bal, contract))) == 0;
		ens_name = None;
		if network == "mainnet":
			ens_name = ns.name(contract);

		contract_name = "Externally Owned Account";

		if not ens_name is None:
			print("\tENS name found:", ens_name);

		if not is_eoa:
			# Get ABI from Etherscan
			abi = etherscanApiUrlGetAbi(bal, contract);
			source_code = etherscanApiUrlGetSourceCode(bal, contract);

			if abi is None or source_code is None:
				print("Contract", contract, "may be unverified!")
				continue;

			code = source_code[0];
			contract_name = code["ContractName"];

			# Find all downstream addresses
			(output_addresses, output_labels) = findAddressesGenericContract(mc, contract, abi);
			addresses.extend(output_addresses);
			labels.extend(output_labels);

			# Find hardcoded addresses
			(output_addresses, output_labels) = findHardCodedAddresses(source_code);
			addresses.extend(output_addresses);
			labels.extend(output_labels);

			# Check to see if contract is EIP-1967 Transparent Proxy
			(output_addresses, output_labels) = analyzeEip1967ProxyContract(bal, contract, abi);
			addresses.extend(output_addresses);
			labels.extend(output_labels);

			# Find active roles
			(output_addresses, output_labels) = findActiveRoles(bal, contract, abi, source_code);
			addresses.extend(output_addresses);
			labels.extend(output_labels);

			# Check to see if contract is a Gnosis Safe Proxy
			(output_addresses, output_labels) = analyzeGnosisSafe(bal, contract, abi);
			addresses.extend(output_addresses);
			labels.extend(output_labels);

			# Read as Proxy
			for a,l in zip(addresses, labels):
				if "implementation" in l.lower():
					proxy_abi = etherscanApiUrlGetAbi(bal, a);
					if proxy_abi is None:
						print("Contract", a, "may be unverified!")
					else:
						(output_addresses, output_labels) = findAddressesGenericContract(mc, contract, proxy_abi);
						addresses.extend(output_addresses);
						labels.extend(output_labels);

		name_string = contract_name + "\n";
		if not ens_name is None:
			 name_string += ens_name + " (" + contract + ")";
		else:
			 name_string += contract;
		contract_names[contract] = name_string

		# Add all discovered addresses to the graph
		for address, label in zip(addresses, labels):
			if not address in contracts:
				contracts.append(address);
				G.add_node(address);
				G.add_edge(contract, address, label=label);

		print();

	# Add Contract names to node labels

	G = nx.relabel_nodes(G, contract_names);

	# Visualization
	pos = nx.spring_layout(G);
	nx.draw(G, pos, with_labels=True, font_weight='bold', font_size=6);
	labels_raw = nx.get_edge_attributes(G,'label');
	labels = {(l[0], l[1]):labels_raw[l] for l in labels_raw};
	nx.draw_networkx_edge_labels(G, pos=pos, edge_labels=labels, font_size=6);
	plt.show();

if __name__ == '__main__':
	main()