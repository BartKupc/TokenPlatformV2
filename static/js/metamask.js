/**
 * MetaMask Integration for Token Platform V2
 * Handles wallet connection, transaction signing, and blockchain interactions
 */

class MetaMaskService {
    constructor() {
        this.isConnected = false;
        this.currentAccount = null;
        this.currentNetwork = null;
        this.requiredNetworkId = '0x7a69'; // Hardhat local network (31337 in decimal)
        this.requiredNetworkName = 'Hardhat Local';
        
        // Initialize on page load
        this.init();
        
        // Listen for account/network changes
        this.setupEventListeners();
    }
    
    async init() {
        // Check if MetaMask is installed
        if (typeof window.ethereum === 'undefined') {
            console.log('MetaMask not installed');
            this.updateUI('not_installed');
            return;
        }
        
        // Check if already connected
        try {
            const accounts = await window.ethereum.request({ method: 'eth_accounts' });
            if (accounts.length > 0) {
                await this.handleAccountsChanged(accounts);
            } else {
                this.updateUI('not_connected');
            }
        } catch (error) {
            console.error('Error checking MetaMask connection:', error);
            this.updateUI('not_connected');
        }
        
        // Check network
        try {
            const chainId = await window.ethereum.request({ method: 'eth_chainId' });
            console.log('🔍 MetaMask: Initial network check:', chainId);
            await this.handleChainChanged(chainId);
        } catch (error) {
            console.error('❌ MetaMask: Error checking network:', error);
            this.updateUI('wrong_network');
        }
    }
    
    setupEventListeners() {
        if (typeof window.ethereum !== 'undefined') {
            // Listen for account changes
            window.ethereum.on('accountsChanged', this.handleAccountsChanged.bind(this));
            
            // Listen for network changes
            window.ethereum.on('chainChanged', this.handleChainChanged.bind(this));
            
            // Listen for connection status changes
            window.ethereum.on('connect', this.handleConnect.bind(this));
            window.ethereum.on('disconnect', this.handleDisconnect.bind(this));
        }
    }
    
    async connectWallet() {
        if (typeof window.ethereum === 'undefined') {
            alert('MetaMask is not installed. Please install MetaMask to use this feature.');
            return;
        }
        
        try {
            // Request account access
            const accounts = await window.ethereum.request({ 
                method: 'eth_requestAccounts' 
            });
            
            if (accounts.length > 0) {
                await this.handleAccountsChanged(accounts);
            }
        } catch (error) {
            console.error('Error connecting to MetaMask:', error);
            if (error.code === 4001) {
                alert('Please connect your MetaMask wallet to continue.');
            } else {
                alert('Error connecting to MetaMask: ' + error.message);
            }
        }
    }
    
    async disconnectWallet() {
        this.isConnected = false;
        this.currentAccount = null;
        this.currentNetwork = null;
        this.updateUI('not_connected');
        
        // Clear any stored connection state
        localStorage.removeItem('metamask_connected');
        localStorage.removeItem('metamask_account');
    }
    
    async handleAccountsChanged(accounts) {
        if (accounts.length === 0) {
            // MetaMask is locked or user has no accounts
            this.isConnected = false;
            this.currentAccount = null;
            this.updateUI('not_connected');
        } else if (accounts[0] !== this.currentAccount) {
            this.currentAccount = accounts[0];
            this.isConnected = true;
            
            // Store connection state
            localStorage.setItem('metamask_connected', 'true');
            localStorage.setItem('metamask_account', this.currentAccount);
            
            // Check network after account change
            try {
                const chainId = await window.ethereum.request({ method: 'eth_chainId' });
                await this.handleChainChanged(chainId);
            } catch (error) {
                console.error('Error checking network after account change:', error);
            }
        }
    }
    
    async handleChainChanged(chainId) {
        this.currentNetwork = chainId;
        console.log('🔍 MetaMask: Network changed to:', chainId);
        console.log('🔍 MetaMask: Expected network:', this.requiredNetworkId);
        
        if (chainId === this.requiredNetworkId) {
            console.log('✅ MetaMask: Correct network detected');
            this.updateUI('connected');
        } else {
            console.log('⚠️ MetaMask: Wrong network detected');
            this.updateUI('wrong_network');
        }
    }
    
    async handleConnect(connectInfo) {
        console.log('MetaMask connected:', connectInfo);
        // Connection status will be updated by handleAccountsChanged
    }
    
    async handleDisconnect(error) {
        console.log('MetaMask disconnected:', error);
        this.isConnected = false;
        this.currentAccount = null;
        this.currentNetwork = null;
        this.updateUI('not_connected');
        
        // Clear stored connection state
        localStorage.removeItem('metamask_connected');
        localStorage.removeItem('metamask_account');
    }
    
    updateUI(status) {
        const statusElement = document.getElementById('metamask-status');
        const networkElement = document.getElementById('metamask-network');
        const connectButton = document.getElementById('metamask-connect');
        const disconnectButton = document.getElementById('metamask-disconnect');
        
        if (!statusElement || !networkElement || !connectButton || !disconnectButton) {
            console.log('⚠️ MetaMask: Some UI elements not found:', {
                statusElement: !!statusElement,
                networkElement: !!networkElement,
                connectButton: !!connectButton,
                disconnectButton: !!disconnectButton
            });
            return;
        }
        
        switch (status) {
            case 'connected':
                statusElement.innerHTML = `<span class="badge bg-success"><i class="fas fa-link"></i> Connected: ${this.currentAccount ? this.currentAccount.substring(0, 6) + '...' + this.currentAccount.substring(38) : 'Unknown'}</span>`;
                networkElement.innerHTML = `<span class="badge bg-success"><i class="fas fa-check"></i> ${this.requiredNetworkName}</span>`;
                connectButton.style.display = 'none';
                disconnectButton.style.display = 'inline-block';
                break;
                
            case 'wrong_network':
                statusElement.innerHTML = `<span class="badge bg-warning"><i class="fas fa-exclamation-triangle"></i> Connected: ${this.currentAccount ? this.currentAccount.substring(0, 6) + '...' + this.currentAccount.substring(38) : 'Unknown'}</span>`;
                networkElement.innerHTML = `<span class="badge bg-warning"><i class="fas fa-exclamation-triangle"></i> Wrong Network (${this.currentNetwork})</span>`;
                connectButton.style.display = 'none';
                disconnectButton.style.display = 'inline-block';
                break;
                
            case 'not_connected':
                statusElement.innerHTML = `<span class="badge bg-secondary"><i class="fas fa-unlink"></i> Not Connected</span>`;
                networkElement.innerHTML = `<span class="badge bg-secondary"><i class="fas fa-unlink"></i> No Network</span>`;
                connectButton.style.display = 'inline-block';
                disconnectButton.style.display = 'none';
                break;
                
            case 'not_installed':
                statusElement.innerHTML = `<span class="badge bg-danger"><i class="fas fa-times"></i> MetaMask Not Installed</span>`;
                networkElement.innerHTML = `<span class="badge bg-danger"><i class="fas fa-times"></i> No Network</span>`;
                connectButton.style.display = 'none';
                disconnectButton.style.display = 'none';
                break;
        }
    }
    
    isWalletConnected() {
        return this.isConnected && this.currentAccount && this.currentNetwork === this.requiredNetworkId;
    }
    
    getCurrentAccount() {
        return this.currentAccount;
    }
    
    async signTransaction(transactionData) {
        if (!this.isWalletConnected()) {
            throw new Error('Wallet not connected');
        }
        
        try {
            // Ensure we have the current account
            const accounts = await window.ethereum.request({ method: 'eth_accounts' });
            if (accounts.length === 0) {
                throw new Error('No accounts found');
            }
            
            const fromAddress = accounts[0];
            console.log('🔍 MetaMask: Using account:', fromAddress);
            console.log('🔍 MetaMask: Transaction data received:', transactionData);
            
            // Prepare transaction for signing
            const transaction = {
                to: transactionData.to,
                data: transactionData.data,
                value: transactionData.value || '0x0',
                gas: transactionData.gas,
                gasPrice: transactionData.gasPrice || '0x0',
                nonce: transactionData.nonce || '0x0',
                chainId: transactionData.chainId || '0x539' // 1337 in hex
            };
            
            console.log('🔍 MetaMask: Prepared transaction:', transaction);
            
            // Request transaction signature
            console.log('🔍 MetaMask: Requesting transaction signature...');
            const txHash = await window.ethereum.request({
                method: 'eth_sendTransaction',
                params: [transaction]
            });
            
            console.log('✅ MetaMask: Transaction sent successfully:', txHash);
            
            return {
                success: true,
                txHash: txHash
            };
            
        } catch (error) {
            console.error('❌ MetaMask: Error signing transaction:', error);
            
            // Provide more specific error messages
            let errorMessage = error.message;
            if (error.code === 4001) {
                errorMessage = 'Transaction rejected by user';
            } else if (error.code === -32603) {
                errorMessage = 'Transaction execution failed: ' + (error.data?.message || error.message);
            } else if (error.code === -32000) {
                errorMessage = 'Invalid request: ' + error.message;
            }
            
            return {
                success: false,
                error: errorMessage,
                code: error.code
            };
        }
    }
}

// Initialize MetaMask service when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.metaMaskService = new MetaMaskService();
});
