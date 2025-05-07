#include "openfhe.h"
#include <chrono>
#include <iostream>
#include <vector>
#include <random>
#include <fstream>
#include <unistd.h>
#include <sys/wait.h>
#include <cstdlib>

using namespace lbcrypto;
using namespace std::chrono;


// Generate random RANKED ballots (each voter ranks all candidates)
std::vector<std::vector<int64_t>> GenerateRankedVotes(int numOptions, int numVotes, unsigned int randomSeed) {
    std::vector<std::vector<int64_t>> votes;
    std::default_random_engine generator(randomSeed);

    for (int v = 0; v < numVotes; ++v) {
        std::vector<int64_t> ranking(numOptions);
        for (int i = 0; i < numOptions; ++i)
            ranking[i] = i;
        std::shuffle(ranking.begin(), ranking.end(), generator);
        votes.push_back(ranking);
    }

    std::cout << "Generated " << numVotes << " ranked ballots." << std::endl;
    return votes;
}

std::vector<std::vector<int64_t>> ConvertToPermutationMatrix(const std::vector<int64_t>& ranking) {
    int numOptions = ranking.size();
    std::vector<std::vector<int64_t>> matrix(numOptions, std::vector<int64_t>(numOptions, 0));

    for (int candidate = 0; candidate < numOptions; ++candidate) {
        int rank = ranking[candidate]; // Candidate C is ranked R
        matrix[rank][candidate] = 1;   // Row = rank, Col = candidate
    }

    return matrix;
}


// Function to get the current memory usage of the calling process, works only in linux
size_t GetMemoryUsage()
{
    std::ifstream statm("/proc/self/statm");
    size_t memoryUsage = 0;
    if (statm.is_open())
    {
        statm >> memoryUsage;                 // Resident memory in pages
        memoryUsage *= sysconf(_SC_PAGESIZE); // Convert pages to bytes
    }
    return memoryUsage; // Memory in bytes
}


// Function to generate Votes (manual, CSV or random)
std::vector<std::vector<int64_t>> GenerateVotes(int numOptions, int numVotes, unsigned int randomSeed, bool isManualVoting, const std::string& csvFilePath) {
    std::vector<std::vector<int64_t>> votes;

    if (isManualVoting) {
        // Manual voting logic
        std::cout << "Manual voting enabled. Enter your votes (one option per vote, valid options are 1-" << numOptions << "):\n";
        for (int i = 0; i < numVotes; ++i) {
            int userVote;
            do {
                std::cout << "Vote " << i + 1 << ": ";
                std::cin >> userVote;
                if (userVote < 1 || userVote > numOptions) {
                    std::cout << "Invalid option. Please vote again.\n";
                }
            } while (userVote < 1 || userVote > numOptions);
            std::vector<int64_t> vote(numOptions, 0);
            vote[userVote - 1] = 1; // Record vote
            votes.push_back(vote);
        }
    } else if (!csvFilePath.empty()) {
        // Open the CSV file
        std::ifstream file(csvFilePath);
        if (!file.is_open()) {
            throw std::runtime_error("Error: Unable to open CSV file.");
        }

        std::cout << "Processing CSV file: " << csvFilePath << "\n";

        std::string line;
        int lineCount = 0;

        while (std::getline(file, line)) {
            // Increment line count for debugging
            ++lineCount;
            
            // Skip empty lines
            if (line.empty()) {
                std::cerr << "Warning: Skipping empty line at " << lineCount << "\n";
                continue;
            }

            std::vector<int64_t> vote(numOptions, 0);
            std::stringstream lineStream(line);
            std::string cell;
            int i = 0;        

            while (std::getline(lineStream, cell, ';')) { // ';' as delimiter
                if (i >= numOptions) {
                    throw std::runtime_error("Error: Too many options in a row at line " + std::to_string(lineCount));
                } 
                vote[i++] = std::strtol(cell.c_str(), nullptr, 10); // Convert to integer
            }

            if (i != numOptions) {
                throw std::runtime_error("Error: Not enough options in a row at line " + std::to_string(lineCount));
            }

            votes.push_back(vote);
        }

        file.close();

        // Verify the number of votes matches the expectation
        if (votes.size() != static_cast<size_t>(numVotes)) {
            throw std::runtime_error("Error: Number of votes in CSV file does not match expected count (" +
                                     std::to_string(votes.size()) + " vs " + std::to_string(numVotes) + ").");
        }

        std::cout << "Votes successfully loaded from CSV file. Total votes: " << votes.size() << "\n";
    } else {
        // Random vote generation
        std::default_random_engine generator(randomSeed);
        std::uniform_int_distribution<int> distribution(0, numOptions - 1);
        for (int i = 0; i < numVotes; ++i) {
            std::vector<int64_t> vote(numOptions, 0);
            int selectedOption = distribution(generator);
            vote[selectedOption] = 1; // Generate random vote
            votes.push_back(vote);
        }
        std::cout << "Random votes generated.\n";
    }

    return votes;
}


//check for CSV file
bool IsFileAccessible(const std::string& filePath) {
    std::ifstream file(filePath);
    return file.good(); // Returns true if the file exists and is accessible
}



// Function to simulate voting with user-defined options and votes
void RunVotingSchemeWithUserInput(const CryptoContext<DCRTPoly> &cryptoContext, const std::string &schemeName, int numOptions, int numVotes, unsigned int randomSeed, const std::vector<std::vector<int64_t>> *preGeneratedVotes)
{
    std::cout << "Running Voting Scheme with " << schemeName << " Scheme\n";

    // Display voting options
    std::cout << "Voting Options: ";
    for (int i = 0; i < numOptions; ++i)
    {
        std::cout << "Option " << i + 1;
        if (i < numOptions - 1)
            std::cout << ", ";
    }
    std::cout << "\nTotal Number of Votes: " << numVotes << "\n";

    // Input votes
    std::vector<std::vector<int64_t>> votes(numVotes, std::vector<int64_t>(numOptions, 0));
    votes = *preGeneratedVotes;

    // Key Generation
    size_t memStart = GetMemoryUsage();
    auto start = high_resolution_clock::now();
    auto startTotal = start;
    auto keyPair = cryptoContext->KeyGen();
    auto end = high_resolution_clock::now();
    auto keyGenTime = duration_cast<milliseconds>(end - start).count();

    // Generate Evaluation Keys - need for mulltiplication or rotation
    start = high_resolution_clock::now();
    //cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    //cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, -1});
    end = high_resolution_clock::now();
    auto evalKeysTime = duration_cast<milliseconds>(end - start).count();

    // Encrypt Votes
    std::vector<Ciphertext<DCRTPoly>> encryptedVotes;

    start = high_resolution_clock::now();
    for (const auto &vote : votes)
    {
        Plaintext plaintextVote = cryptoContext->MakePackedPlaintext(vote);
        auto ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintextVote);
        encryptedVotes.push_back(ciphertext);
    }
    end = high_resolution_clock::now();
    auto encryptionTime = duration_cast<milliseconds>(end - start).count();

    // Perform Homomorphic Addition (aggregate votes)
    start = high_resolution_clock::now();
    auto totalVotes = encryptedVotes[0];
    for (size_t i = 1; i < encryptedVotes.size(); i++)
    {
        totalVotes = cryptoContext->EvalAdd(totalVotes, encryptedVotes[i]);
    }
    end = high_resolution_clock::now();
    auto evalTime = duration_cast<milliseconds>(end - start).count();

    // Decrypt Result
    Plaintext result;
    start = high_resolution_clock::now();
    cryptoContext->Decrypt(keyPair.secretKey, totalVotes, &result);
    end = high_resolution_clock::now();
    auto endTotal = end;
    auto decryptionTime = duration_cast<milliseconds>(end - start).count();

    result->SetLength(numOptions); // Limit to the number of options
    size_t memEnd = GetMemoryUsage();

    auto evalTimeTotal = duration_cast<milliseconds>(endTotal - startTotal).count();
    auto votesPerSec = ((float)numVotes) / (evalTimeTotal / 1000.0);

    // Output Results
    std::cout << "Runtime Details:\n";
    std::cout << "  Key Generation Time: " << keyGenTime << " ms\n";
    std::cout << "  Evaluation Keys Generation Time: " << evalKeysTime << " ms\n";
    std::cout << "  Encryption Time: " << encryptionTime << " ms\n";
    std::cout << "  Evaluation Time (Addition): " << evalTime << " ms\n";
    std::cout << "  Decryption Time: " << decryptionTime << " ms\n";
    std::cout << "  Total Time: " << evalTimeTotal << "ms\n";
    std::cout << "  Votes per Sec: " << votesPerSec << "\n";
    std::cout << "  Memory Usage before: " << memStart / (1024 * 1024) << " MB\n";
    std::cout << "  Memory Usage after: " << memEnd / (1024 * 1024) << " MB\n";
    std::cout << "  Memory Usage Total: " << (memEnd - memStart) / (1024 * 1024) << " MB\n";

    std::cout << "\nVoting Results:\n";
    for (int i = 0; i < numOptions; ++i)
    {
        std::cout << "  Option " << i + 1 << ": " << result->GetPackedValue()[i] << " votes\n";
    }

    // Plaintext vote aggregation
    std::vector<int64_t> plaintextTotal(numOptions, 0);
    for (const auto &vote : votes)
    {
        for (int i = 0; i < numOptions; ++i)
        {
            plaintextTotal[i] += vote[i];
        }
    }

    // Validate homomorphic result
    bool isValid = true;
    for (int i = 0; i < numOptions; ++i)
    {
        if (result->GetPackedValue()[i] != plaintextTotal[i])
        {
            isValid = false;
            std::cerr << "Validation Failed: Option " << i + 1 << " does not match. "
                      << "Expected: " << plaintextTotal[i]
                      << ", Decrypted: " << result->GetPackedValue()[i] << "\n";
        }
    }
    if (isValid)
    {
        std::cout << "Validation Passed: Homomorphic and plaintext results match.\n";
    }
    else
    {
        std::cerr << "Validation Failed: Discrepancy detected.\n";
    }

    std::cout << std::endl;
    exit(0);
}



int main()
{
    // User-defined parameters
    int numOptions = 5;     // Number of voting options
    int numVotes = 100;      // Number of voters
    unsigned int randomSeed = static_cast<unsigned>(std::chrono::system_clock::now().time_since_epoch().count()); // to have the same random voting for each algorithm
    bool manualVoting = false;
    std::string csvFilePath = "";   //if empty random votes are generated, manual Voting must be false




    std::vector<std::vector<int64_t>> generatedVotes;
    generatedVotes = GenerateVotes(numOptions, numVotes, randomSeed, manualVoting, csvFilePath);




    // Setup BFV CryptoContext
    CCParams<CryptoContextBFVRNS> paramsBFV;
    paramsBFV.SetPlaintextModulus(65537); // 2^16+1
    paramsBFV.SetMultiplicativeDepth(1);
    auto cryptoContextBFV = GenCryptoContext(paramsBFV);
    cryptoContextBFV->Enable(PKE);
    cryptoContextBFV->Enable(LEVELEDSHE);

    // Setup BGV CryptoContext
    CCParams<CryptoContextBGVRNS> paramsBGV;
    paramsBGV.SetPlaintextModulus(65537);
    paramsBGV.SetMultiplicativeDepth(1);
    auto cryptoContextBGV = GenCryptoContext(paramsBGV);
    cryptoContextBGV->Enable(PKE);
    cryptoContextBGV->Enable(LEVELEDSHE);

    // fork is used because its memory is separated from each other fork so no biased memory measurement is taken
    // Fork process for BFV
    pid_t pidBFV = fork();
    if (pidBFV == 0)
    {
        // Child process for BFV
        RunVotingSchemeWithUserInput(cryptoContextBFV, "BFV", numOptions, numVotes, randomSeed, &generatedVotes);
    }
    else if (pidBFV > 0)
    {
        // Parent process waits for BFV to finish
        int statusBFV;
        waitpid(pidBFV, &statusBFV, 0);
        if (WIFEXITED(statusBFV))
        {
            std::cout << "BFV Process Completed Successfully.\n";
        }
        else
        {
            std::cerr << "BFV Process Failed.\n";
        }

        // Fork process for BGV
        pid_t pidBGV = fork();
        if (pidBGV == 0)
        {
            // Child process for BGV
            RunVotingSchemeWithUserInput(cryptoContextBGV, "BGV", numOptions, numVotes, randomSeed, &generatedVotes);
        }
        else if (pidBGV > 0)
        {
            // Parent process waits for BGV to finish
            int statusBGV;
            waitpid(pidBGV, &statusBGV, 0);
            if (WIFEXITED(statusBGV))
            {
                std::cout << "BGV Process Completed Successfully.\n";
            }
            else
            {
                std::cerr << "BGV Process Failed.\n";
            }
        }
        else
        {
            std::cerr << "Failed to fork for BGV process.\n";
            return 1;
        }
    }
    else
    {
        std::cerr << "Failed to fork for BFV process.\n";
        return 1;
    }
}
