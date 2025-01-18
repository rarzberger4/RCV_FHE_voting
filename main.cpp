#include "openfhe.h"
#include <chrono>
#include <iostream>
#include <vector>
#include <random>

using namespace lbcrypto;
using namespace std::chrono;

// Function to simulate voting with user-defined options and votes
void RunVotingSchemeWithUserInput(const CryptoContext<DCRTPoly>& cryptoContext, const std::string& schemeName, 
                                  int numOptions, int numVotes) {
    std::cout << "Running Voting Scheme with " << schemeName << " Scheme\n";

    // Display voting options
    std::cout << "Voting Options: ";
    for (int i = 0; i < numOptions; ++i) {
        std::cout << "Option " << i + 1;
        if (i < numOptions - 1) std::cout << ", ";
    }
    std::cout << "\nTotal Number of Votes: " << numVotes << "\n";

    // Generate random votes (one-hot encoding)
    std::vector<std::vector<int64_t>> votes(numVotes, std::vector<int64_t>(numOptions, 0));
    std::default_random_engine generator;
    std::uniform_int_distribution<int> distribution(0, numOptions - 1);

    for (auto& vote : votes) {
        int selectedOption = distribution(generator);
        vote[selectedOption] = 1; // Only one option is voted per vote
    }

    // Key Generation
    auto start = high_resolution_clock::now();
    auto keyPair = cryptoContext->KeyGen();
    auto end = high_resolution_clock::now();
    auto keyGenTime = duration_cast<milliseconds>(end - start).count();

    // Generate Evaluation Keys
    start = high_resolution_clock::now();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, -1});
    end = high_resolution_clock::now();
    auto evalKeysTime = duration_cast<milliseconds>(end - start).count();

    // Encrypt Votes
    std::vector<Ciphertext<DCRTPoly>> encryptedVotes;

    start = high_resolution_clock::now();
    for (const auto& vote : votes) {
        Plaintext plaintextVote = cryptoContext->MakePackedPlaintext(vote);
        auto ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintextVote);
        encryptedVotes.push_back(ciphertext);
    }
    end = high_resolution_clock::now();
    auto encryptionTime = duration_cast<milliseconds>(end - start).count();

    // Perform Homomorphic Addition (aggregate votes)
    start = high_resolution_clock::now();
    auto totalVotes = encryptedVotes[0];
    for (size_t i = 1; i < encryptedVotes.size(); i++) {
        totalVotes = cryptoContext->EvalAdd(totalVotes, encryptedVotes[i]);
    }
    end = high_resolution_clock::now();
    auto evalTime = duration_cast<milliseconds>(end - start).count();

    // Decrypt Result
    Plaintext result;
    start = high_resolution_clock::now();
    cryptoContext->Decrypt(keyPair.secretKey, totalVotes, &result);
    end = high_resolution_clock::now();
    auto decryptionTime = duration_cast<milliseconds>(end - start).count();

    result->SetLength(numOptions); // Limit to the number of options


    // Output Results
    std::cout << "Runtime Details:\n";
    std::cout << "  Key Generation Time: " << keyGenTime << " ms\n";
    std::cout << "  Evaluation Keys Generation Time: " << evalKeysTime << " ms\n";
    std::cout << "  Encryption Time: " << encryptionTime << " ms\n";
    std::cout << "  Evaluation Time (Addition): " << evalTime << " ms\n";
    std::cout << "  Decryption Time: " << decryptionTime << " ms\n";

    std::cout << "Voting Results:\n";
    for (int i = 0; i < numOptions; ++i) {
        std::cout << "  Option " << i + 1 << ": " << result->GetPackedValue()[i] << " votes\n";
    }

    std::cout << std::endl;
}

int main() {
    // User-defined parameters
    int numOptions = 30;   // Number of voting options
    int numVotes = 1000;  // Number of votes

    // Setup BFV CryptoContext
    CCParams<CryptoContextBFVRNS> paramsBFV;
    paramsBFV.SetPlaintextModulus(65537);
    paramsBFV.SetMultiplicativeDepth(2);
    auto cryptoContextBFV = GenCryptoContext(paramsBFV);
    cryptoContextBFV->Enable(PKE);
    cryptoContextBFV->Enable(LEVELEDSHE);

    // Setup BGV CryptoContext
    CCParams<CryptoContextBGVRNS> paramsBGV;
    paramsBGV.SetPlaintextModulus(65537);
    paramsBGV.SetMultiplicativeDepth(2);
    auto cryptoContextBGV = GenCryptoContext(paramsBGV);
    cryptoContextBGV->Enable(PKE);
    cryptoContextBGV->Enable(LEVELEDSHE);


    // Run voting schemes
    RunVotingSchemeWithUserInput(cryptoContextBFV, "BFV", numOptions, numVotes);
    RunVotingSchemeWithUserInput(cryptoContextBGV, "BGV", numOptions, numVotes);

    return 0;
}
