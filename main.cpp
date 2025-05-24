#include "openfhe.h"
#include <chrono>
#include <iostream>
#include <vector>
#include <random>
#include <fstream>
#include <unistd.h>
#include <sys/wait.h>
#include <cstdlib>
#include <ctime>
#include <iomanip>

using namespace lbcrypto;
using namespace std::chrono;



void WriteCSVHeader(const std::string& filename) {
    std::ofstream file(filename, std::ios::app);
    if (file.tellp() == 0) {
        file << "Timestamp,Scheme,Options,Votes,Encrypt(ms),Add(ms),Decrypt(ms),Total(ms),CipherSize(Bytes),PeakMemory(MB)\n";
    }
    file.close();
}

void WriteCSVRow(const std::string& filename, const std::string& scheme,int numOptions, int numVotes,
                 long encrypt, long add, long decrypt, long total,
                 size_t ctSize, size_t peakMemMB)
{
    std::ofstream file(filename, std::ios::app);
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    file << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S") << ",";
    file << scheme << "," << numOptions << "," << numVotes << "," << encrypt << "," << add << "," << decrypt << ","
         << total << "," << ctSize << "," << peakMemMB << "\n";
    file.close();
}


void RunForkedBenchmark(const std::function<void()> &fn) {
    pid_t pid = fork();
    if (pid == 0) {
        fn();
        exit(0);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    } else {
        std::cerr << "❌ Fork failed!\n";
        exit(1);
    }
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


int FindLowestCandidate(
    const std::vector<int64_t>& tally,
    const std::vector<int>& eliminated)
{
    int minVotes = std::numeric_limits<int>::max();
    std::vector<int> tiedCandidates;

    //Find the minimum vote count among non-eliminated candidates
    for (size_t i = 0; i < tally.size(); ++i) {
        if (std::find(eliminated.begin(), eliminated.end(), i) == eliminated.end()) {
            if (tally[i] < minVotes) {
                minVotes = tally[i];
                tiedCandidates = {static_cast<int>(i)};
            } else if (tally[i] == minVotes) {
                tiedCandidates.push_back(static_cast<int>(i));
            }
        }
    }

    //If there's a tie, break it by selecting the lowest index
    if (tiedCandidates.size() > 1) {
        // Deterministic tie resolution: always pick the lowest index
        return *std::min_element(tiedCandidates.begin(), tiedCandidates.end());
    }else {
        return tiedCandidates[0];
    }
}

int RunIRVElection(
    std::vector<std::vector<std::vector<int64_t>>> plaintextBallots,
    CryptoContext<DCRTPoly> cc,
    const KeyPair<DCRTPoly> &keypair,
    const std::string& schemeName,
    const std::string& csvFilename,
    int numOptions,
    int numVotes)
{
    size_t memStart = GetMemoryUsage();
    auto startTotal = high_resolution_clock::now();

    int numCandidates = plaintextBallots[0][0].size();
    std::vector<int> eliminated;

    // Measure encryption
    auto start = high_resolution_clock::now();
    std::vector<std::vector<Ciphertext<DCRTPoly>>> encryptedBallots;
    for (const auto &matrix : plaintextBallots) {
        encryptedBallots.push_back(EncryptBallotRows(matrix, cc, keypair.publicKey));
    }
    auto end = high_resolution_clock::now();
    long encryptTime = duration_cast<milliseconds>(end - start).count();

    // Measure addition
    start = high_resolution_clock::now();
    Ciphertext<DCRTPoly> total = encryptedBallots[0][0];
    for (size_t i = 1; i < encryptedBallots.size(); ++i) {
        total = cc->EvalAdd(total, encryptedBallots[i][0]);
    }
    end = high_resolution_clock::now();
    long addTime = duration_cast<milliseconds>(end - start).count();

    // Measure decryption
    Plaintext result;
    start = high_resolution_clock::now();
    cc->Decrypt(keypair.secretKey, total, &result);
    end = high_resolution_clock::now();
    long decryptTime = duration_cast<milliseconds>(end - start).count();

    result->SetLength(numCandidates);
    std::vector<int64_t> tally = result->GetPackedValue();

    std::cout << "Decrypted First-Choice Tally:\n";
    for (size_t i = 0; i < tally.size(); ++i)
        std::cout << "  Candidate " << i << ": " << tally[i] << " votes\n";

    auto endTotal = high_resolution_clock::now();
    long totalTime = duration_cast<milliseconds>(endTotal - startTotal).count();
    size_t memEnd = GetMemoryUsage();
    size_t peakMemMB = (memEnd - memStart) / (1024 * 1024);

    std::stringstream ss;
    Serial::Serialize(*encryptedBallots[0][0], ss, SerType::BINARY);
    size_t ctSize = ss.str().size();

    WriteCSVHeader(csvFilename);
    WriteCSVRow(csvFilename, schemeName, numOptions, numVotes, encryptTime, addTime, decryptTime, totalTime, ctSize, peakMemMB);

    while (true) {
        // Majority check
        int totalActiveVotes = 0;
        for (int i = 0; i < numCandidates; ++i)
            if (std::find(eliminated.begin(), eliminated.end(), i) == eliminated.end())
                totalActiveVotes += tally[i];

        for (int i = 0; i < numCandidates; ++i) {
            if (std::find(eliminated.begin(), eliminated.end(), i) == eliminated.end() &&
                tally[i] > totalActiveVotes / 2) {
                std::cout << "🎉 Winner: Candidate " << i << " 🎉\n";
                return i;
            }
        }

        // Stop if only one candidate remains
        int remaining = 0;
        int potentialWinner = -1;
        for (int i = 0; i < numCandidates; ++i) {
            if (std::find(eliminated.begin(), eliminated.end(), i) == eliminated.end()) {
                remaining++;
                potentialWinner = i;
            }
        }
        if (remaining == 1) {
            std::cout << "🎉 Winner by elimination: Candidate " << potentialWinner << " 🎉\n";
            return potentialWinner;
        }

        // Eliminate lowest
        int toEliminate = FindLowestCandidate(tally, eliminated);
        std::cout << "Eliminated Candidate: " << toEliminate << "\n\n";
        eliminated.push_back(toEliminate);

        // Update plaintext ballots
        std::vector<std::vector<std::vector<int64_t>>> updatedBallots;
        for (auto &matrix : plaintextBallots) {
            std::vector<std::vector<int64_t>> cleaned;
            for (auto &row : matrix) {
                row[toEliminate] = 0;
                if (std::any_of(row.begin(), row.end(), [](int64_t v) { return v == 1; })) {
                    cleaned.push_back(row);
                }
            }
            updatedBallots.push_back(cleaned);
        }
        plaintextBallots = updatedBallots;

        // Re-encrypt
        encryptedBallots.clear();
        for (const auto &matrix : plaintextBallots) {
            encryptedBallots.push_back(EncryptBallotRows(matrix, cc, keypair.publicKey));
        }

        // Tally again
        total = encryptedBallots[0][0];
        for (size_t i = 1; i < encryptedBallots.size(); ++i) {
            total = cc->EvalAdd(total, encryptedBallots[i][0]);
        }

        cc->Decrypt(keypair.secretKey, total, &result);
        result->SetLength(numCandidates);
        tally = result->GetPackedValue();

        std::cout << "Decrypted First-Choice Tally:\n";
        for (size_t i = 0; i < tally.size(); ++i)
            std::cout << "  Candidate " << i << ": " << tally[i] << " votes\n";
    }

    std::cerr << "No winner found!\n";
    return -1;
}




int main() {
    std::cout.setf(std::ios::unitbuf);  // Auto-flush stdout for child output

    std::vector<int> candidateOptions = {4, 5};
    std::vector<int> voteCounts = {100, 200};
    int repetitions = 2;

    // Setup BFV CryptoContext
    CCParams<CryptoContextBFVRNS> paramsBFV;
    paramsBFV.SetPlaintextModulus(65537);
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

    for (int numOptions : candidateOptions) {
        for (int numVotes : voteCounts) {
            for (int rep = 0; rep < repetitions; ++rep) {
                std::cout << "\n=== Run " << (rep + 1)
                          << " | Options: " << numOptions
                          << " | Votes: " << numVotes << " ===\n";

                unsigned int randomSeed = static_cast<unsigned>(
                    std::chrono::system_clock::now().time_since_epoch().count()) + rep;

                std::vector<std::vector<int64_t>> generatedVotes =
                    GenerateVotes(numOptions, numVotes, randomSeed);

                // --- BFV Benchmark ---
                RunForkedBenchmark([&]() {
                    std::cout << "--- BFV Benchmark --- (PID: " << getpid()
                              << ", Parent: " << getppid() << ")\n";

                    auto keyPair = cryptoContextBFV->KeyGen();

                    std::vector<std::vector<std::vector<int64_t>>> plaintextBallots;
                    for (const auto &vote : generatedVotes)
                        plaintextBallots.push_back(ConvertToPermutationMatrix(vote));

                    RunIRVElection(plaintextBallots, cryptoContextBFV, keyPair,
                                   "BFV", "bfv_results.csv", numOptions, numVotes);
                });

                // --- BGV Benchmark ---
                RunForkedBenchmark([&]() {
                    std::cout << "--- BGV Benchmark --- (PID: " << getpid()
                              << ", Parent: " << getppid() << ")\n";

                    auto keyPair = cryptoContextBGV->KeyGen();

                    std::vector<std::vector<std::vector<int64_t>>> plaintextBallots;
                    for (const auto &vote : generatedVotes)
                        plaintextBallots.push_back(ConvertToPermutationMatrix(vote));

                    RunIRVElection(plaintextBallots, cryptoContextBGV, keyPair,
                                   "BGV", "bgv_results.csv", numOptions, numVotes);
                });
            }
        }
    }

    std::cout << "\n✅ All benchmarks completed.\n";
    return 0;
}
