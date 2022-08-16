//
// Created by 47133 on 2022/8/10.
//
#include <iostream>

#include "UnitTest.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Endpoint.h"
#include "cryptoTools/Network/IOService.h"

#include "cryptoTools/Common/Defines.h"
//#include "libPSI/Tools/RandomShuffle.h"
//#include "../frontend/bloomFilterMain.h"
//#include "../frontend/dcwMain.h"
//#include "../frontend/dktMain.h"
//#include "../frontend/ecdhMain.h"
//#include "../frontend/OtBinMain.h"
//#include "../frontend/util.h"

//#include "cryptoTools/Common/MatrixView.h"
//#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
//#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include <fstream>
#include <numeric>
#include <chrono>
#include <thread>
//#include "tests_cryptoTools/UnitTests.h"
//#include "libOTe_Tests/UnitTests.h"
//#include "libPSI_Tests/UnitTests.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
//#include "libPSI/PIR/BgiPirClient.h"
//#include "libPSI/PIR/BgiPirServer.h"
//#include "cryptoTools/Crypto/RandomOracle.h"

//#include "../frontend/cuckoo/cuckooTests.h"
#include "cryptoTools/Common/CLP.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libPSI/PSI/Kkrt/KkrtPsiReceiver.h"
#include "libPSI/PSI/Kkrt/KkrtPsiSender.h"


using namespace osuCrypto;
void kkrt_PSI(std::string path, std::string outpath, u64 bucketNum, std::string ip, u64 port, u64 statSetParam, int r);
void BucketByFile(const u32 &bucketNum,
                  const std::string &path,
                  std::vector<std::vector<std::string>> &vecData,
                  const SessionMode &epType);
void BucketByGetLine(const std::string &data,
                     const u32 &bucketNum,
                     std::vector<std::vector<std::string>> &vecData);
void PSIReceiverOrSender(const EpMode &epType,
                         const u32 &bucketNum,
                         std::vector<std::vector<std::string>> &vecData,
                         Endpoint &localEp,
                         Channel &localChannel,
                         std::vector<Channel> &vecChannels,
                         const u64 &statSetParam,
                         std::vector<std::vector<u64>> &vecIntersection);
void RunPsiSender(const u64 &senderSize,
                  const u64 &receiverSize,
                  const std::vector<std::string> &vecSendData,
                  Channel &nthChannel,
                  const u64 &statSetParam);
void RunPsiReceiver(const u64 &senderSize,
                    const u64 &receiverSize,
                    const std::vector<std::string> &vecSendData,
                    Channel &nthChannel,
                    const u64 &statSetParam,
                    std::vector<u64> &eachIntersection);
void writeOutput(std::string outPath, const std::vector<std::vector<u64>>& intersection);
block ItemToBlock(const std::string &dataItem);

//void printTime(std::vector<Channel> channels, long long bucketTime,
//               long long TotalTime, const u64 &setSize, const u64 &numThreads);
//void printTTime(std::vector<Channel> channels, long long bucketTime,
//               long long TotalTime, const u64 &numThreads);
//enum class Role {
//    Sender = 0,
//    Receiver = 1,
//    Invalid
//};

int main(int argc, char const* const* argv)
{
//    std::cout << "hhhhhhhhhhh\n";
//    CLP cmd;
//    cmd.parse(argc, argv);

//    cmd.setDefault("bucket" , "2");
//    cmd.setDefault("in","../../../testdata/data1.csv");

    std::thread t1(kkrt_PSI,"/data/zbydata/testdata/tenMilData2.csv", "/data/zbydata/testdata/res.csv.out",
                   30, "127.0.0.1", 1212, 40, 1);
    std::thread t2(kkrt_PSI,"/data/zbydata/testdata/tenMilData1.csv", "/data/zbydata/testdata/res.csv.out",
                   30, "127.0.0.1", 1212, 40, 0);

    t1.join();
    t2.join();

    return 0;
}

//void printTime(std::vector<Channel> channels, long long bucketTime,
//               long long TotalTime, const u64 &setSize, const u64 &numThreads)
//{
//    u64 dataSent(0);
//    u64 dataRecv(0);
//    for (u64 i = 0; i < channels.size(); ++i) {
//        dataSent += channels[i].getTotalDataSent();
//        dataRecv += channels[i].getTotalDataRecv();
//        channels[i].resetStats();
//    }
//    std::cout << " n = " << setSize << "\n"
//                  << " threads = " << numThreads << "\n"
//                  << " bucket Time = " << bucketTime << " ms\n"
//                  << " Total Time = " <<TotalTime << " ms\n"
//                  << " Total Comm = " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB\n";
//
//
//}
//
//void printTTime(std::vector<Channel> channels, long long bucketTime,
//               long long TotalTime, const u64 &numThreads)
//{
//    u64 dataSent(0);
//    u64 dataRecv(0);
//    for (u64 i = 0; i < channels.size(); ++i) {
//        dataSent += channels[i].getTotalDataSent();
//        dataRecv += channels[i].getTotalDataRecv();
//        channels[i].resetStats();
//    }
//    std::cout << " threads = " << numThreads << "\n"
//                  << " bucket Time = " << bucketTime << " ms\n"
//                  << " Total Time = " <<TotalTime << " ms\n"
//                  << " Total Comm = " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB\n";
//
//
//}

void kkrt_PSI(std::string path, std::string outpath, u64 bucketNum, std::string ip, u64 port, u64 statSetParam, int r)
{
    try {
        Timer timer;

//        auto path = cmd.get<std::string>("in");//输入文件路径
//        std::cout << "path " << path << std::endl;
//        auto outPath = cmd.getOr<std::string>("out", path + ".out");//输出文件路径
//
//        Timer wholeTimer;
//         std::cout << "readfile" << std::endl;
//         auto readfile = wholeTimer.setTimePoint("readfile");
//
//         std::vector <block> set = readSet(path);
//
//        u64 statSetParam = cmd.getOr("ssp", 40);//统计安全参数
//        auto ip = cmd.getOr<std::string>("ip", "localhost:1212");//server ip
//        auto bucketNum = cmd.getOr<int>("bucket", 1);//分桶数
        auto start = timer.setTimePoint("start");
        std::vector<std::vector<std::string>> vecData(bucketNum);//数据分桶，每个桶存放数据的string形式
        std::vector<std::vector<u64>> vecIntersection(bucketNum);//交集结果
        //        auto r = (Role) cmd.getOr<int>("r", 2);//角色 0：sender/client 1：receiver/server
        if (r != 1 && r != 0)
            throw std::runtime_error("-r tag must be set with value 0 (sender) or 1 (receiver).");

        //auto isServer = cmd.getOr<int>("server", (int) r);
        // if (r != Role::Sender && r != Role::Receiver)
        //     throw std::runtime_error("-server tag must be set with value 0 or 1.");

        //auto mode = isServer ? SessionMode::Server : SessionMode::Client;
        //std::cout << "-----------in kkrtPSI-------1-------" << std::endl;
//#if defined(ENABLE_KKRT) && defined(ENABLE_KKRT_PSI)
        // std::cout << "-----------in kkrtPSI-------1.5-------" << std::endl;
			std::string strExchangeSize = "exchangeSize";

            if (r == 0)
				{//r = 0 :client && sender

					IOService ios;
					std::string str_main_chlname = "main_channel";
    				std::string str_close_chlname = "close_channel";

					BucketByFile(bucketNum, path, vecData, SessionMode::Client);
                    //std::cout << "-----------in kkrtPSI-------1.6-------" << std::endl;
					//auto afterBucket = timer.setTimePoint("afterBucket");
                    Endpoint localEp(ios, ip, port, EpMode::Client, strExchangeSize);
					Channel localChannel = localEp.addChannel(str_main_chlname, str_main_chlname);
					Channel localCloseChannel = localEp.addChannel(str_close_chlname, str_close_chlname);
					std::vector<Channel> vecChannels(bucketNum);
                    //std::cout << "-----------in kkrtPSI-------2-------" << std::endl;
					PSIReceiverOrSender(EpMode::Client,
							bucketNum,
							vecData,
							localEp,
							localChannel,
							vecChannels,
							statSetParam,
							vecIntersection);

					u64 u_close;
					localCloseChannel.recv(u_close);
					for (auto i = 0; i < bucketNum; i++)
					{
						vecChannels[i].close();
					}
					localCloseChannel.close();
					localChannel.close();
					localEp.stop();
					ios.stop();
					}
				else
				{//r = 1 :server && receiver
					IOService ios;
					std::string str_main_chlname = "main_channel";
    				std::string str_close_chlname = "close_channel";
                    BucketByFile(bucketNum, path, vecData, SessionMode::Server);
                    auto afterBucket = timer.setTimePoint("afterBucket");
//                    std::cout << "-----------in kkrtPSI-------1.6-------" << std::endl;
					Endpoint localEp(ios, ip, port, EpMode::Server, strExchangeSize);
					Channel localChannel = localEp.addChannel(str_main_chlname, str_main_chlname);
					Channel localCloseChannel = localEp.addChannel(str_close_chlname, str_close_chlname);

					std::vector<Channel> vecChannels(bucketNum);
//                    std::cout << "-----------in kkrtPSI-------2-------" << std::endl;
					PSIReceiverOrSender(EpMode::Server,
							bucketNum,
							vecData,
							localEp,
							localChannel,
							vecChannels,
							statSetParam,
							vecIntersection);


                    writeOutput(outpath, vecIntersection);
                    auto end = timer.setTimePoint("end");

                    auto totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                    auto bucketTime = std::chrono::duration_cast<std::chrono::milliseconds>(afterBucket - start).count();

//                    std::cout << "Total Time is " << totalTime << " ms\n";
//                    std::cout << "bucket Time is " << bucketTime<< " ms\n";

//                    printTTime(vecChannels, bucketTime,totalTime, bucketNum);

					u64 u_close = 123;
                    u64 dataSent = 0, dataRecv = 0;
					localCloseChannel.send(u_close);
					for (auto i = 0; i < bucketNum; i++)
					{
                        dataSent += vecChannels[i].getTotalDataSent();
                        dataRecv += vecChannels[i].getTotalDataRecv();
                        vecChannels[i].close();
					}

					localCloseChannel.close();
					localChannel.close();
					localEp.stop();
					ios.stop();
                    std::cout << "done\n";

                    std::cout << "Total Time is " << totalTime << " ms\n";
                    std::cout << "bucket Time is " << bucketTime<< " ms\n";
                    std::cout << "Total Comm is " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB\n";


            }
//#else
//        throw std::runtime_error("ENABLE_KKRT_PSI not defined.");
//#endif

    }catch (std::exception& e)
    {
        std::cout << Color::Red << "Exception: " << e.what() << std::endl << Color::Default;

        std::cout << "Try adding command line argument -debug" << std::endl;
    }
}


/**
    * @description: 将文件分桶到vecData
    * @param {u32} &bucketNum 分桶数
    * @param {string} &path 输入文件路径
    * @param {	vector	} vecData 分桶
    * @param {SessionMode} &epType 模式
    * @return {*}
    */
void BucketByFile(const u32 &bucketNum,
                  const std::string &path,
                  std::vector<std::vector<std::string>> &vecData,
                  const SessionMode &epType)
{
//        std::cout << "-----------in BucketByFile-------------" << std::endl;
    std::hash<std::string> hashStr;
    std::ifstream localIfFile(path, std::ios::in);
    if (localIfFile.is_open() == false)
        throw std::runtime_error("failed to open file: " + path);
//        std::cout << "-----------in BucketByFile--1-----------" << std::endl;
    BucketByGetLine(path, bucketNum, vecData);

    for (auto i = 0; i < bucketNum; ++i)
    {
        if(vecData[i].empty())//空桶补dummy元素
        {
            std::string strValue;
            //r = 0 :client && sender
            //r = 1 :server && receiver
            if(epType == SessionMode::Server)
            {
                strValue = "server dummy item";
                std::cout<< "The receiver bucket [" << i<< "] is empty\n";
            }
            else
            {
                strValue = "client dummy item";
                std::cout<< "The sender bucket [" << i<< "] is empty\n";
            }
            vecData[hashStr(strValue) % bucketNum].emplace_back(strValue);
        }

    }

}

/**
     * @description: 将文件每行分桶放入vecData
     * @param {string} &data 文件路径
     * @param {u32} &bucketNum 分桶数
     * @param {	vector	} vecData 分桶，存放string类型
     * @return {*}
     */
void BucketByGetLine(const std::string &data,
                     const u32 &bucketNum,
                     std::vector<std::vector<std::string>> &vecData)
{
    u64 n = 0;
//        std::cout << "-----------in BucketByGetLine-------------" << std::endl;
    std::ifstream dataFile(data, std::ios::in);
    if (dataFile.is_open() == false)
        throw std::runtime_error("failed to open file: " + data);
//        std::cout << "-----------in BucketByGetLine----1---------" << std::endl;
    std::string dataItem;//存放每行输入
    std::hash<std::string> hashStr;

//        std::cout << "-----------in BucketByGetLine-----2--------" << std::endl;
    while(std::getline(dataFile, dataItem))
    {
//            std::cout << "dataItem = " << dataItem << std::endl;
        n++;
        auto k = hashStr(dataItem) % (bucketNum);
//            std::cout << "k = " << k << std::endl;
        vecData[k].emplace_back(dataItem);//放入对应桶中
//            std::cout << "-----------vecData["<< k <<"]input "<< dataItem <<"-------------" << std::endl;
    }
    std::cout << "n = " << n << std::endl;
}

/**
  * @description: 根据分桶数起线程分别执行PSI，结果统一放至vecIntersection
  * @param {EpMode} &epType 模式
  * @param {u32} &bucketNum 分桶数
  * @param {vector	} vecData 各分桶
  * @param {Endpoint} &localEp 长连接
  * @param {Channel} &localChannel 传递size的channel
  * @param {vector		} vecChannels 放置各个线程建立的channel的容器
  * @param {u64} statSetParam 统计安全参数
  * @param {vector<u64>} &vecIntersection 交集结果
  * @return {*}
  */
void PSIReceiverOrSender(const EpMode &epType,
                         const u32 &bucketNum,
                         std::vector<std::vector<std::string>> &vecData,
                         Endpoint &localEp,
                         Channel &localChannel,
                         std::vector<Channel> &vecChannels,
                         const u64 &statSetParam,
                         std::vector<std::vector<u64>> &vecIntersection)
{
    //std::cout << "vecData.size:" << vecData.size() << std::endl;
    std::vector<u64> vecSenderSize(bucketNum );//sender 各桶元素数
    std::vector<u64> vecReceiverSize(bucketNum ) ;//receiver 各桶元素数
    std::vector<u64> vecDataSize(bucketNum );//本方各桶元素数

    std::vector<std::thread> vecThreads(bucketNum);//每分桶一个线程
    for (int i = 0; i < bucketNum; i++)
    {
        /* code */
        vecDataSize[i] = (u64)vecData[i].size();
    }
    if(epType == EpMode::Client)
    {//r = 0 :client && sender
        if(localChannel.isConnected())
        {
            std::cout << "client channel is connected " << std::endl;
        }
        else
        {
            std::cout << "client channel is not connected " << std::endl;

        }
        for (auto i = 0; i < bucketNum; i++)
        {
            /* code */
            localChannel.asyncSend(vecDataSize[i]);
        }

        for (auto i = 0; i < bucketNum; i++)
        {
            /* code */
            localChannel.recv(vecReceiverSize[i]);
        }
        for (auto i = 0; i < bucketNum; i++)
        {
            /* code */
            vecChannels[i] = localEp.addChannel(std::to_string(i + 1), std::to_string(i + 1));

        }

        for (u32 i = 0; i < bucketNum; i++)
        {
            /* code */
            if(vecChannels[i].isConnected())
            {
                std::cout << "client channel "<< i + 1 <<" is connected " << std::endl;

            }
            else
            {
                std::cout << "client channel "<< i + 1 <<" is not connected " << std::endl;

            }

            //std::cout << "------------\n";

            vecThreads[i] = std::thread(RunPsiSender,
                                        vecDataSize[i],
                                        std::ref(vecReceiverSize[i]),
                                        std::ref(vecData[i]),
                                        std::ref(vecChannels[i]),
                                        std::ref(statSetParam));
            //std::cout << "bucket[" << i << "] is done\n";

        }

        //std::cout << "client" << std::endl;
        for (int i = 0; i < bucketNum; ++i) {
            vecThreads[i].join();

        }

    }
    else
    {//EpMode::Server
        if(localChannel.isConnected())
        {
            std::cout << "server channel is connected " << std::endl;
        }
        else
        {
            std::cout << "server channel is not connected " << std::endl;

        }
        for (auto i = 0; i < bucketNum; i++)
        {
            /* code */
            localChannel.asyncSend(vecDataSize[i]);
        }
        for (auto i = 0; i < bucketNum; i++)
        {
            /* code */
            localChannel.recv(vecSenderSize[i]);
        }
        for (auto i = 0; i < bucketNum; i++)
        {
            /* code */
            vecChannels[i] = localEp.addChannel(std::to_string(i + 1), std::to_string(i + 1));

        }
        for (u32 i = 0; i < bucketNum; i++)
        {
            /* code */
            if(vecChannels[i].isConnected())
            {
                std::cout << "server channel "<< i + 1 <<" is connected " << std::endl;

            }
            else
            {
                std::cout << "server channel "<< i + 1 <<" is not connected " << std::endl;

            }

            vecThreads[i] = std::thread(RunPsiReceiver,
                                        std::ref(vecSenderSize[i]),
                                        vecDataSize[i],
                                        std::ref(vecData[i]),
                                        std::ref(vecChannels[i]),
                                        std::ref(statSetParam),
                                        std::ref(vecIntersection[i]));


        }
        //std::cout << "Server" << std::endl;
        for (int i = 0; i < bucketNum; ++i) {
            vecThreads[i].join();

        }
    }

}

/**
  * @description: sender每次具体执行流程
  * @param {u64} &senderSize
  * @param {u64} &receiverSize
  * @param {vector<std::string>} &vecSendData 本方每次psi的输入数据，类型为string
  * @param {Channel} &nthChannel 对应的channel
  * @param {u64} statSetParam 统计安全参数
  * @return {*}
  */
void RunPsiSender(const u64 &senderSize,
                  const u64 &receiverSize,
                  const std::vector<std::string> &vecSendData,
                  Channel &nthChannel,
                  const u64 &statSetParam)
{
    std::vector<block> vecBlockData;//将每个桶中元素转化为block类型
    for (auto i = 0; i < vecSendData.size(); i++)
    {
        /* code */
        vecBlockData.emplace_back(ItemToBlock(vecSendData[i]));
    }
    KkrtNcoOtSender ot;
    KkrtPsiSender sender;
    sender.init(senderSize, receiverSize, statSetParam, nthChannel, ot, sysRandomSeed());
    sender.sendInput(vecBlockData, nthChannel);
    std::cout << "sender is done\n";

}

/**
  * @description: receiver每次具体执行流程
  * @param {u64} &senderSize
  * @param {u64} &receiverSize
  * @param {vector<std::string>} &vecSendData 本方每次psi的输入数据，类型为string
  * @param {Channel} &nthChannel 对应的channel
  * @param {u64} statSetParam 统计安全参数
  * @param {vector<u64>} &vecIntersection 交集输出
  * @return {*}
  */
void RunPsiReceiver(const u64 &senderSize,
                    const u64 &receiverSize,
                    const std::vector<std::string> &vecSendData,
                    Channel &nthChannel,
                    const u64 &statSetParam,
                    std::vector<u64> &eachIntersection)
{
    std::vector<block> vecBlockData;//将每个桶中元素转化为block类型
    for (auto i = 0; i < vecSendData.size(); i++)
    {
        /* code */
        vecBlockData.emplace_back(ItemToBlock(vecSendData[i]));
    }

    KkrtNcoOtReceiver ot;
    KkrtPsiReceiver recver;
    recver.init(senderSize, receiverSize, statSetParam, nthChannel, ot, sysRandomSeed());
    recver.sendInput(vecBlockData, nthChannel);
    u64 tempu64;
    std::stringstream ss;

    for (auto i : recver.mIntersection)//recver.mintersection存放每次交集对应的输入数据的顺序
    {
        ss << vecSendData[i];
        ss >> tempu64;
        eachIntersection.emplace_back(tempu64);
    }
    std::cout << "recver is done\n";
}

void writeOutput(std::string outPath, const std::vector<std::vector<u64>>& intersection)
{
    std::ofstream file;
    file.open(outPath, std::ios::out | std::ios::trunc);

    if (file.is_open() == false)
        throw std::runtime_error("failed to open the output file: " + outPath);
    for (auto i = 0; i < intersection.size(); ++i) {
        for (auto j : intersection[i])
        { file << j << "\n"; }
    }


}


block ItemToBlock(const std::string &dataItem)
{
    std::hash<std::string> hash_str;
    u64 tmpDataItem = (u64)hash_str(dataItem);
    return toBlock(tmpDataItem);

}