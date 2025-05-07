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
std::vector<std::vector<int64_t>> GenerateVotes(int numOptions, int numVotes, unsigned int randomSeed)
{
    std::vector<std::vector<int64_t>> votes;
    std::default_random_engine generator(randomSeed);

    for (int v = 0; v < numVotes; ++v)
    {
        std::vector<int64_t> ranking(numOptions);
        for (int i = 0; i < numOptions; ++i)
            ranking[i] = i;
        std::shuffle(ranking.begin(), ranking.end(), generator);
        votes.push_back(ranking);
    }

    std::cout << "Generated " << numVotes << " ranked ballots." << std::endl;
    return votes;
}

// Convert ranked votes to permutation matrix
std::vector<std::vector<int64_t>> ConvertToPermutationMatrix(const std::vector<int64_t> &ranking)
{
    int numOptions = ranking.size();
    std::vector<std::vector<int64_t>> matrix(numOptions, std::vector<int64_t>(numOptions, 0));

    for (int candidate = 0; candidate < numOptions; ++candidate)
    {
        int rank = ranking[candidate]; // Candidate C is ranked R
        matrix[rank][candidate] = 1;   // Row = rank, Col = candidate
    }

    return matrix;
}

// Encrypt the permutation matrix
std::vector<Ciphertext<DCRTPoly>> EncryptBallotRows(
    const std::vector<std::vector<int64_t>> &matrix,
    CryptoContext<DCRTPoly> cc,
    const PublicKey<DCRTPoly> &pk)
{
    std::vector<Ciphertext<DCRTPoly>> encryptedMatrix;

    for (const auto &row : matrix)
    {
        Plaintext pt = cc->MakePackedPlaintext(row);
        Ciphertext<DCRTPoly> ct = cc->Encrypt(pk, pt);
        encryptedMatrix.push_back(ct);
    }

    return encryptedMatrix;
}

std::vector<int64_t> DecryptTallyRow(
    const std::vector<Ciphertext<DCRTPoly>> &row,
    CryptoContext<DCRTPoly> cc,
    const KeyPair<DCRTPoly> &keypair)
{
    Ciphertext<DCRTPoly> total = row[0];
    for (size_t i = 1; i < row.size(); ++i)
        total = cc->EvalAdd(total, row[i]);

    Plaintext result;
    cc->Decrypt(keypair.secretKey, total, &result);
    result->SetLength(row.size());
    return result->GetPackedValue();
}

Ciphertext<DCRTPoly> HomomorphicTally(
    const std::vector<std::vector<Ciphertext<DCRTPoly>>> &encryptedBallots,
    CryptoContext<DCRTPoly> cc)
{
    Ciphertext<DCRTPoly> total = encryptedBallots[0][0]; // Start with first-choice row of first ballot

    for (size_t i = 1; i < encryptedBallots.size(); ++i)
    {
        total = cc->EvalAdd(total, encryptedBallots[i][0]); // Add row 0 (first-choice row) of each ballot
    }

    return total;
}


// Find the candidate with the lowest tally
int FindLowestCandidate(
    const std::vector<int64_t> &tally,
    const std::vector<int> &eliminated)
{
    int minVotes = std::numeric_limits<int>::max();
    int minIndex = -1;

    for (size_t i = 0; i < tally.size(); ++i)
    {
        if (std::find(eliminated.begin(), eliminated.end(), i) == eliminated.end())
        {
            if (tally[i] < minVotes)
            {
                minVotes = tally[i];
                minIndex = i;
            }
        }
    }

    return minIndex;
}

int RunIRVRound(
    const std::vector<std::vector<Ciphertext<DCRTPoly>>> &encryptedBallots,
    CryptoContext<DCRTPoly> cc,
    const KeyPair<DCRTPoly> &keypair,
    const std::vector<int> &alreadyEliminated,
    int numCandidates)
{
    std::cout << "Running IRV Round...\n";

    // 1. Tally encrypted first-choice row across all ballots
    Ciphertext<DCRTPoly> total = HomomorphicTally(encryptedBallots, cc);

    // 2. Decrypt the result
    Plaintext result;
    cc->Decrypt(keypair.secretKey, total, &result);
    result->SetLength(numCandidates);       // Limit to the number of candidates  TODO !!!
    std::vector<int64_t> tally = result->GetPackedValue();

    // 3. Print decrypted tallies
    std::cout << "Decrypted First-Choice Tally:\n";
    for (size_t i = 0; i < tally.size(); ++i)
    {
        std::cout << "  Candidate " << i << ": " << tally[i] << " votes\n";
    }

    // 4. Eliminate lowest non-eliminated candidate
    int toEliminate = FindLowestCandidate(tally, alreadyEliminated);
    std::cout << "Eliminated Candidate: " << toEliminate << "\n\n";

    return toEliminate;
}

int RunIRVElection(
    std::vector<std::vector<std::vector<int64_t>>> plaintextBallots,
    CryptoContext<DCRTPoly> cc,
    const KeyPair<DCRTPoly> &keypair)
{
    int numCandidates = plaintextBallots[0][0].size();
    std::vector<int> eliminated;

    while (static_cast<int>(eliminated.size()) < numCandidates - 1)
    {
        // Encrypt current ballots
        std::vector<std::vector<Ciphertext<DCRTPoly>>> encryptedBallots;
        for (const auto &matrix : plaintextBallots)
        {
            encryptedBallots.push_back(EncryptBallotRows(matrix, cc, keypair.publicKey));
        }

        // Run one IRV round
        int eliminatedCandidate = RunIRVRound(encryptedBallots, cc, keypair, eliminated, numCandidates);
        eliminated.push_back(eliminatedCandidate);

        // Prepare updated ballots
        std::vector<std::vector<std::vector<int64_t>>> updatedBallots;

        for (auto &matrix : plaintextBallots)
        {
            std::vector<std::vector<int64_t>> cleaned;

            for (auto &row : matrix)
            {
                row[eliminatedCandidate] = 0;

                if (std::any_of(row.begin(), row.end(), [](int64_t v) { return v == 1; }))
                {
                    cleaned.push_back(row);
                }
            }

            updatedBallots.push_back(cleaned);
        }

        // Replace old ballots with updated ones
        plaintextBallots = updatedBallots;
    }

    // Declare winner
    for (int i = 0; i < numCandidates; ++i)
    {
        if (std::find(eliminated.begin(), eliminated.end(), i) == eliminated.end())
        {
            std::cout << "🎉 Winner: Candidate " << i << " 🎉\n";
            return i;
        }
    }

    std::cerr << "No winner found!\n";
    return -1;
}






std::vector<std::vector<Ciphertext<DCRTPoly>>> ShiftAndReencryptBallots(
    const std::vector<std::vector<std::vector<int64_t>>> &plaintextBallots,
    int eliminatedCandidate,
    CryptoContext<DCRTPoly> cc,
    const PublicKey<DCRTPoly> &pk)
{
    std::vector<std::vector<Ciphertext<DCRTPoly>>> encryptedShifted;

    for (const auto &matrix : plaintextBallots)
    {
        std::vector<std::vector<int64_t>> newMatrix;

        // Step 1: zero out the eliminated candidate
        std::vector<std::vector<int64_t>> shifted = matrix;
        for (auto &row : shifted)
            row[eliminatedCandidate] = 0;

        // Step 2: re-normalize into valid permutation matrix
        // Remove rows with all zeros (if any), then re-rank
        for (const auto &row : shifted)
        {
            bool hasOne = std::any_of(row.begin(), row.end(), [](int64_t v)
                                      { return v == 1; });
            if (hasOne)
                newMatrix.push_back(row);
        }

        // Step 3: Encrypt each row
        std::vector<Ciphertext<DCRTPoly>> encryptedRows;
        for (const auto &row : newMatrix)
        {
            Plaintext pt = cc->MakePackedPlaintext(row);
            encryptedRows.push_back(cc->Encrypt(pk, pt));
        }

        encryptedShifted.push_back(encryptedRows);
    }

    return encryptedShifted;
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




int main()
{
    // User-defined parameters
    int numOptions = 4;                                                                                           // Number of voting options
    int numVotes = 100;                                                                                           // Number of voters
    unsigned int randomSeed = static_cast<unsigned>(std::chrono::system_clock::now().time_since_epoch().count()); // to have the same random voting for each algorithm

    std::vector<std::vector<int64_t>> generatedVotes;
    generatedVotes = GenerateVotes(numOptions, numVotes, randomSeed);

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
        std::cout << "\n=== Running IRV with BFV ===\n";

        size_t memStart = GetMemoryUsage();
        auto start = high_resolution_clock::now();

        auto keyPair = cryptoContextBFV->KeyGen();

        std::vector<std::vector<std::vector<int64_t>>> plaintextBallots;
        for (const auto &vote : generatedVotes)
        {
            plaintextBallots.push_back(ConvertToPermutationMatrix(vote));
        }

        RunIRVElection(plaintextBallots, cryptoContextBFV, keyPair);

        auto end = high_resolution_clock::now();
        size_t memEnd = GetMemoryUsage();

        std::cout << "BFV Total Time: " << duration_cast<milliseconds>(end - start).count() << " ms\n";
        std::cout << "Memory Used: " << (memEnd - memStart) / (1024 * 1024) << " MB\n";

        exit(0);
    }
    else if (pidBFV > 0)
    {
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
            std::cout << "\n=== Running IRV with BGV ===\n";

            size_t memStart = GetMemoryUsage();
            auto start = high_resolution_clock::now();

            auto keyPair = cryptoContextBGV->KeyGen();

            std::vector<std::vector<std::vector<int64_t>>> plaintextBallots;
            for (const auto &vote : generatedVotes)
            {
                plaintextBallots.push_back(ConvertToPermutationMatrix(vote));
            }

            RunIRVElection(plaintextBallots, cryptoContextBGV, keyPair);

            auto end = high_resolution_clock::now();
            size_t memEnd = GetMemoryUsage();

            std::cout << "BGV Total Time: " << duration_cast<milliseconds>(end - start).count() << " ms\n";
            std::cout << "Memory Used: " << (memEnd - memStart) / (1024 * 1024) << " MB\n";

            exit(0);
        }
        else if (pidBGV > 0)
        {
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
