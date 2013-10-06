    for (int i = 0; i < (int)keypoints.size(); ++i)
    {
        uchar* desc = descriptors.ptr(i);
        const KeyPoint& pt = keypoints[i];

        desc[0] =((smoothedSum(sum, pt, pattern[0].first.second, pattern[0].first.first) < smoothedSum(sum, pt, pattern[0].second.second, pattern[0].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[1].first.second, pattern[1].first.first) < smoothedSum(sum, pt, pattern[1].second.second, pattern[1].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[2].first.second, pattern[2].first.first) < smoothedSum(sum, pt, pattern[2].second.second, pattern[2].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[3].first.second, pattern[3].first.first) < smoothedSum(sum, pt, pattern[3].second.second, pattern[3].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[4].first.second, pattern[4].first.first) < smoothedSum(sum, pt, pattern[4].second.second, pattern[4].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[5].first.second, pattern[5].first.first) < smoothedSum(sum, pt, pattern[5].second.second, pattern[5].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[6].first.second, pattern[6].first.first) < smoothedSum(sum, pt, pattern[6].second.second, pattern[6].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[7].first.second, pattern[7].first.first) < smoothedSum(sum, pt, pattern[7].second.second, pattern[7].second.first)) << 0);
        desc[1] =((smoothedSum(sum, pt, pattern[8].first.second, pattern[8].first.first) < smoothedSum(sum, pt, pattern[8].second.second, pattern[8].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[9].first.second, pattern[9].first.first) < smoothedSum(sum, pt, pattern[9].second.second, pattern[9].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[10].first.second, pattern[10].first.first) < smoothedSum(sum, pt, pattern[10].second.second, pattern[10].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[11].first.second, pattern[11].first.first) < smoothedSum(sum, pt, pattern[11].second.second, pattern[11].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[12].first.second, pattern[12].first.first) < smoothedSum(sum, pt, pattern[12].second.second, pattern[12].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[13].first.second, pattern[13].first.first) < smoothedSum(sum, pt, pattern[13].second.second, pattern[13].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[14].first.second, pattern[14].first.first) < smoothedSum(sum, pt, pattern[14].second.second, pattern[14].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[15].first.second, pattern[15].first.first) < smoothedSum(sum, pt, pattern[15].second.second, pattern[15].second.first)) << 0);
        desc[2] =((smoothedSum(sum, pt, pattern[16].first.second, pattern[16].first.first) < smoothedSum(sum, pt, pattern[16].second.second, pattern[16].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[17].first.second, pattern[17].first.first) < smoothedSum(sum, pt, pattern[17].second.second, pattern[17].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[18].first.second, pattern[18].first.first) < smoothedSum(sum, pt, pattern[18].second.second, pattern[18].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[19].first.second, pattern[19].first.first) < smoothedSum(sum, pt, pattern[19].second.second, pattern[19].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[20].first.second, pattern[20].first.first) < smoothedSum(sum, pt, pattern[20].second.second, pattern[20].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[21].first.second, pattern[21].first.first) < smoothedSum(sum, pt, pattern[21].second.second, pattern[21].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[22].first.second, pattern[22].first.first) < smoothedSum(sum, pt, pattern[22].second.second, pattern[22].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[23].first.second, pattern[23].first.first) < smoothedSum(sum, pt, pattern[23].second.second, pattern[23].second.first)) << 0);
        desc[3] =((smoothedSum(sum, pt, pattern[24].first.second, pattern[24].first.first) < smoothedSum(sum, pt, pattern[24].second.second, pattern[24].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[25].first.second, pattern[25].first.first) < smoothedSum(sum, pt, pattern[25].second.second, pattern[25].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[26].first.second, pattern[26].first.first) < smoothedSum(sum, pt, pattern[26].second.second, pattern[26].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[27].first.second, pattern[27].first.first) < smoothedSum(sum, pt, pattern[27].second.second, pattern[27].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[28].first.second, pattern[28].first.first) < smoothedSum(sum, pt, pattern[28].second.second, pattern[28].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[29].first.second, pattern[29].first.first) < smoothedSum(sum, pt, pattern[29].second.second, pattern[29].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[30].first.second, pattern[30].first.first) < smoothedSum(sum, pt, pattern[30].second.second, pattern[30].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[31].first.second, pattern[31].first.first) < smoothedSum(sum, pt, pattern[31].second.second, pattern[31].second.first)) << 0);
    }