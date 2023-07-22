import json
import sys

import balpy
from multicaller import multicaller

import networkx as nx
import matplotlib.pyplot as plt

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
ZERO_BYTES = "0x0000000000000000000000000000000000000000000000000000000000000000";

def bytes32ToAddress(bytes_data):
	return("0x" + bytes_data[-40:]);

def etherscanApiUrlGetAbi(bal, address):
	urlString = "/api?module=contract&action=getabi&address={}&apikey=".format(address);
	success = False;
	results = None;
	while not success:
		try:
			abi = bal.callEtherscan(urlString);
			results = json.loads(abi["result"]);
			success = True;
		except KeyboardInterrupt:
			print("Caught Ctrl+C");
			quit();
		except Exception as e:
			print(e);
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
		outputData = mc.execute();
		for outputs in outputData[0]:
			for element in outputs:
				addresses.append(element);

		filtered_addresses = [];
		filtered_fn_names = [];

		for a, n in zip(addresses, fn_names):
			if not a == ZERO_ADDRESS:
				filtered_addresses.append(a);
				filtered_fn_names.append(n);

		return(filtered_addresses, filtered_fn_names)

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

def analyzeProxyContract(bal, contract, abi):
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
			# address = asdf;
			w3 = bal.web3;
			# bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
			implementation_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
			impl_data = str(getStorageAtSlot(w3, contract, implementation_slot));
			if not impl_data == ZERO_BYTES:
				addresses.append(bytes32ToAddress(impl_data));
				labels.append("Proxy Implementation");

			# bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)
			beacon_slot = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
			beacon_data = str(getStorageAtSlot(w3, contract, beacon_slot));
			if not beacon_data == ZERO_BYTES:
				addresses.append(bytes32ToAddress(beacon_data));
				labels.append("Proxy Beacon");

			# bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)
			admin_slot = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
			admin_data = str(getStorageAtSlot(w3, contract, admin_slot));
			if not admin_data == ZERO_BYTES:
				addresses.append(bytes32ToAddress(admin_data));
				labels.append("Proxy Admin");

		return(addresses, labels);

def getTimelockControllerProposers(bal, contract, abi):
	addresses = [];
	labels = [];

	isTimelockController = False;
	roleGrantedAbiInputs = None;
	roleRevokedAbiInputs = None;
	for fn in abi:
		if "name" in fn:
			if fn["name"] == "TIMELOCK_ADMIN_ROLE":
				isTimelockController = True;
			if fn["name"] == "RoleGranted":
				roleGrantedAbiInputs = fn["inputs"];
			if fn["name"] == "RoleRevoked":
				roleRevokedAbiInputs = fn["inputs"];

	if isTimelockController:
		grantedTopic = generateEventTopic(bal, "RoleGranted", roleGrantedAbiInputs);
		revokedTopic = generateEventTopic(bal, "RoleRevoked", roleRevokedAbiInputs);

		proposer_role = bal.web3.sha3(text="PROPOSER_ROLE").hex();

		proposers = [];
		revoked_proposers = [];
		grantedEvents = getAllInstancesOfEvent(bal, contract, grantedTopic);
		
		# Skipping this for now since something could be added, revoked, and added again
		# revokedEvents = getAllInstancesOfEvent(bal, contract, revokedTopic);
		# for e in revokedEvents:
		# 	role = e["topics"][1]
		# 	if role == proposer_role:
		# 		account = e["topics"][2]
		# 		revoked_proposers.append(account);

		for e in grantedEvents:
			role = e["topics"][1];
			if role == proposer_role:
				account = e["topics"][2];
				if not account in revoked_proposers:
					proposers.append(bytes32ToAddress(account));

		return(proposers, ["PROPOSER"]*len(proposers));
	return([], []);

def main():
	network = "mainnet";
	verbose = False;

	if not len(sys.argv) == 2:
		print("Usage: python", sys.argv[0], "<contract_address>");
		quit();

	root_contract = sys.argv[1];

	contracts = [];
	contracts.append(root_contract);

	# Initialize graph data structure (use multigraph to get edge labels)
	G = nx.MultiGraph();
	G.add_node(root_contract);

	# initialize balpy, multicaller
	bal = balpy.balpy.balpy(network);
	mc = multicaller.multicaller(	_chainId=bal.networkParams[network]["id"],
									_web3=bal.web3,
									_maxRetries=5,
									_verbose=verbose);

	# Iterate through all contracts
	# Note: additional contracts are added to this list as they are found
	for contract in contracts:
		print("Investigating address:", contract);
		addresses = [];
		labels = [];
		
		# Get ABI from Etherscan
		abi = etherscanApiUrlGetAbi(bal, contract);

		# Find all downstream addresses
		(output_addresses, output_labels) = findAddressesGenericContract(mc, contract, abi);
		addresses.extend(output_addresses);
		labels.extend(output_labels);

		# Check to see if contract is EIP-1967 Transparent Proxy
		(output_addresses, output_labels) = analyzeProxyContract(bal, contract, abi);
		addresses.extend(output_addresses);
		labels.extend(output_labels);
		
		# Check to see if contract is an OZ TimelockController
		(output_addresses, output_labels) = getTimelockControllerProposers(bal, contract, abi);
		addresses.extend(output_addresses);
		labels.extend(output_labels);

		# Add all discovered addresses to the graph
		for address, label in zip(addresses, labels):
			contracts.append(address);
			G.add_node(address);
			G.add_edge(contract, address, label=label);

	# Visualization
	pos = nx.spring_layout(G);
	nx.draw(G, pos, with_labels=True, font_weight='bold', font_size=6);
	labels_raw = nx.get_edge_attributes(G,'label');
	labels = {(l[0], l[1]):labels_raw[l] for l in labels_raw};
	nx.draw_networkx_edge_labels(G, pos=pos, edge_labels=labels, font_size=6);
	plt.show();

if __name__ == '__main__':
	main()