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
        desc[4] =((smoothedSum(sum, pt, pattern[32].first.second, pattern[32].first.first) < smoothedSum(sum, pt, pattern[32].second.second, pattern[32].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[33].first.second, pattern[33].first.first) < smoothedSum(sum, pt, pattern[33].second.second, pattern[33].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[34].first.second, pattern[34].first.first) < smoothedSum(sum, pt, pattern[34].second.second, pattern[34].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[35].first.second, pattern[35].first.first) < smoothedSum(sum, pt, pattern[35].second.second, pattern[35].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[36].first.second, pattern[36].first.first) < smoothedSum(sum, pt, pattern[36].second.second, pattern[36].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[37].first.second, pattern[37].first.first) < smoothedSum(sum, pt, pattern[37].second.second, pattern[37].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[38].first.second, pattern[38].first.first) < smoothedSum(sum, pt, pattern[38].second.second, pattern[38].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[39].first.second, pattern[39].first.first) < smoothedSum(sum, pt, pattern[39].second.second, pattern[39].second.first)) << 0);
        desc[5] =((smoothedSum(sum, pt, pattern[40].first.second, pattern[40].first.first) < smoothedSum(sum, pt, pattern[40].second.second, pattern[40].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[41].first.second, pattern[41].first.first) < smoothedSum(sum, pt, pattern[41].second.second, pattern[41].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[42].first.second, pattern[42].first.first) < smoothedSum(sum, pt, pattern[42].second.second, pattern[42].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[43].first.second, pattern[43].first.first) < smoothedSum(sum, pt, pattern[43].second.second, pattern[43].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[44].first.second, pattern[44].first.first) < smoothedSum(sum, pt, pattern[44].second.second, pattern[44].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[45].first.second, pattern[45].first.first) < smoothedSum(sum, pt, pattern[45].second.second, pattern[45].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[46].first.second, pattern[46].first.first) < smoothedSum(sum, pt, pattern[46].second.second, pattern[46].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[47].first.second, pattern[47].first.first) < smoothedSum(sum, pt, pattern[47].second.second, pattern[47].second.first)) << 0);
        desc[6] =((smoothedSum(sum, pt, pattern[48].first.second, pattern[48].first.first) < smoothedSum(sum, pt, pattern[48].second.second, pattern[48].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[49].first.second, pattern[49].first.first) < smoothedSum(sum, pt, pattern[49].second.second, pattern[49].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[50].first.second, pattern[50].first.first) < smoothedSum(sum, pt, pattern[50].second.second, pattern[50].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[51].first.second, pattern[51].first.first) < smoothedSum(sum, pt, pattern[51].second.second, pattern[51].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[52].first.second, pattern[52].first.first) < smoothedSum(sum, pt, pattern[52].second.second, pattern[52].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[53].first.second, pattern[53].first.first) < smoothedSum(sum, pt, pattern[53].second.second, pattern[53].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[54].first.second, pattern[54].first.first) < smoothedSum(sum, pt, pattern[54].second.second, pattern[54].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[55].first.second, pattern[55].first.first) < smoothedSum(sum, pt, pattern[55].second.second, pattern[55].second.first)) << 0);
        desc[7] =((smoothedSum(sum, pt, pattern[56].first.second, pattern[56].first.first) < smoothedSum(sum, pt, pattern[56].second.second, pattern[56].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[57].first.second, pattern[57].first.first) < smoothedSum(sum, pt, pattern[57].second.second, pattern[57].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[58].first.second, pattern[58].first.first) < smoothedSum(sum, pt, pattern[58].second.second, pattern[58].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[59].first.second, pattern[59].first.first) < smoothedSum(sum, pt, pattern[59].second.second, pattern[59].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[60].first.second, pattern[60].first.first) < smoothedSum(sum, pt, pattern[60].second.second, pattern[60].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[61].first.second, pattern[61].first.first) < smoothedSum(sum, pt, pattern[61].second.second, pattern[61].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[62].first.second, pattern[62].first.first) < smoothedSum(sum, pt, pattern[62].second.second, pattern[62].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[63].first.second, pattern[63].first.first) < smoothedSum(sum, pt, pattern[63].second.second, pattern[63].second.first)) << 0);
        desc[8] =((smoothedSum(sum, pt, pattern[64].first.second, pattern[64].first.first) < smoothedSum(sum, pt, pattern[64].second.second, pattern[64].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[65].first.second, pattern[65].first.first) < smoothedSum(sum, pt, pattern[65].second.second, pattern[65].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[66].first.second, pattern[66].first.first) < smoothedSum(sum, pt, pattern[66].second.second, pattern[66].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[67].first.second, pattern[67].first.first) < smoothedSum(sum, pt, pattern[67].second.second, pattern[67].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[68].first.second, pattern[68].first.first) < smoothedSum(sum, pt, pattern[68].second.second, pattern[68].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[69].first.second, pattern[69].first.first) < smoothedSum(sum, pt, pattern[69].second.second, pattern[69].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[70].first.second, pattern[70].first.first) < smoothedSum(sum, pt, pattern[70].second.second, pattern[70].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[71].first.second, pattern[71].first.first) < smoothedSum(sum, pt, pattern[71].second.second, pattern[71].second.first)) << 0);
        desc[9] =((smoothedSum(sum, pt, pattern[72].first.second, pattern[72].first.first) < smoothedSum(sum, pt, pattern[72].second.second, pattern[72].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[73].first.second, pattern[73].first.first) < smoothedSum(sum, pt, pattern[73].second.second, pattern[73].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[74].first.second, pattern[74].first.first) < smoothedSum(sum, pt, pattern[74].second.second, pattern[74].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[75].first.second, pattern[75].first.first) < smoothedSum(sum, pt, pattern[75].second.second, pattern[75].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[76].first.second, pattern[76].first.first) < smoothedSum(sum, pt, pattern[76].second.second, pattern[76].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[77].first.second, pattern[77].first.first) < smoothedSum(sum, pt, pattern[77].second.second, pattern[77].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[78].first.second, pattern[78].first.first) < smoothedSum(sum, pt, pattern[78].second.second, pattern[78].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[79].first.second, pattern[79].first.first) < smoothedSum(sum, pt, pattern[79].second.second, pattern[79].second.first)) << 0);
        desc[10] =((smoothedSum(sum, pt, pattern[80].first.second, pattern[80].first.first) < smoothedSum(sum, pt, pattern[80].second.second, pattern[80].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[81].first.second, pattern[81].first.first) < smoothedSum(sum, pt, pattern[81].second.second, pattern[81].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[82].first.second, pattern[82].first.first) < smoothedSum(sum, pt, pattern[82].second.second, pattern[82].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[83].first.second, pattern[83].first.first) < smoothedSum(sum, pt, pattern[83].second.second, pattern[83].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[84].first.second, pattern[84].first.first) < smoothedSum(sum, pt, pattern[84].second.second, pattern[84].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[85].first.second, pattern[85].first.first) < smoothedSum(sum, pt, pattern[85].second.second, pattern[85].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[86].first.second, pattern[86].first.first) < smoothedSum(sum, pt, pattern[86].second.second, pattern[86].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[87].first.second, pattern[87].first.first) < smoothedSum(sum, pt, pattern[87].second.second, pattern[87].second.first)) << 0);
        desc[11] =((smoothedSum(sum, pt, pattern[88].first.second, pattern[88].first.first) < smoothedSum(sum, pt, pattern[88].second.second, pattern[88].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[89].first.second, pattern[89].first.first) < smoothedSum(sum, pt, pattern[89].second.second, pattern[89].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[90].first.second, pattern[90].first.first) < smoothedSum(sum, pt, pattern[90].second.second, pattern[90].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[91].first.second, pattern[91].first.first) < smoothedSum(sum, pt, pattern[91].second.second, pattern[91].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[92].first.second, pattern[92].first.first) < smoothedSum(sum, pt, pattern[92].second.second, pattern[92].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[93].first.second, pattern[93].first.first) < smoothedSum(sum, pt, pattern[93].second.second, pattern[93].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[94].first.second, pattern[94].first.first) < smoothedSum(sum, pt, pattern[94].second.second, pattern[94].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[95].first.second, pattern[95].first.first) < smoothedSum(sum, pt, pattern[95].second.second, pattern[95].second.first)) << 0);
        desc[12] =((smoothedSum(sum, pt, pattern[96].first.second, pattern[96].first.first) < smoothedSum(sum, pt, pattern[96].second.second, pattern[96].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[97].first.second, pattern[97].first.first) < smoothedSum(sum, pt, pattern[97].second.second, pattern[97].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[98].first.second, pattern[98].first.first) < smoothedSum(sum, pt, pattern[98].second.second, pattern[98].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[99].first.second, pattern[99].first.first) < smoothedSum(sum, pt, pattern[99].second.second, pattern[99].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[100].first.second, pattern[100].first.first) < smoothedSum(sum, pt, pattern[100].second.second, pattern[100].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[101].first.second, pattern[101].first.first) < smoothedSum(sum, pt, pattern[101].second.second, pattern[101].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[102].first.second, pattern[102].first.first) < smoothedSum(sum, pt, pattern[102].second.second, pattern[102].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[103].first.second, pattern[103].first.first) < smoothedSum(sum, pt, pattern[103].second.second, pattern[103].second.first)) << 0);
        desc[13] =((smoothedSum(sum, pt, pattern[104].first.second, pattern[104].first.first) < smoothedSum(sum, pt, pattern[104].second.second, pattern[104].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[105].first.second, pattern[105].first.first) < smoothedSum(sum, pt, pattern[105].second.second, pattern[105].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[106].first.second, pattern[106].first.first) < smoothedSum(sum, pt, pattern[106].second.second, pattern[106].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[107].first.second, pattern[107].first.first) < smoothedSum(sum, pt, pattern[107].second.second, pattern[107].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[108].first.second, pattern[108].first.first) < smoothedSum(sum, pt, pattern[108].second.second, pattern[108].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[109].first.second, pattern[109].first.first) < smoothedSum(sum, pt, pattern[109].second.second, pattern[109].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[110].first.second, pattern[110].first.first) < smoothedSum(sum, pt, pattern[110].second.second, pattern[110].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[111].first.second, pattern[111].first.first) < smoothedSum(sum, pt, pattern[111].second.second, pattern[111].second.first)) << 0);
        desc[14] =((smoothedSum(sum, pt, pattern[112].first.second, pattern[112].first.first) < smoothedSum(sum, pt, pattern[112].second.second, pattern[112].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[113].first.second, pattern[113].first.first) < smoothedSum(sum, pt, pattern[113].second.second, pattern[113].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[114].first.second, pattern[114].first.first) < smoothedSum(sum, pt, pattern[114].second.second, pattern[114].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[115].first.second, pattern[115].first.first) < smoothedSum(sum, pt, pattern[115].second.second, pattern[115].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[116].first.second, pattern[116].first.first) < smoothedSum(sum, pt, pattern[116].second.second, pattern[116].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[117].first.second, pattern[117].first.first) < smoothedSum(sum, pt, pattern[117].second.second, pattern[117].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[118].first.second, pattern[118].first.first) < smoothedSum(sum, pt, pattern[118].second.second, pattern[118].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[119].first.second, pattern[119].first.first) < smoothedSum(sum, pt, pattern[119].second.second, pattern[119].second.first)) << 0);
        desc[15] =((smoothedSum(sum, pt, pattern[120].first.second, pattern[120].first.first) < smoothedSum(sum, pt, pattern[120].second.second, pattern[120].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[121].first.second, pattern[121].first.first) < smoothedSum(sum, pt, pattern[121].second.second, pattern[121].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[122].first.second, pattern[122].first.first) < smoothedSum(sum, pt, pattern[122].second.second, pattern[122].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[123].first.second, pattern[123].first.first) < smoothedSum(sum, pt, pattern[123].second.second, pattern[123].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[124].first.second, pattern[124].first.first) < smoothedSum(sum, pt, pattern[124].second.second, pattern[124].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[125].first.second, pattern[125].first.first) < smoothedSum(sum, pt, pattern[125].second.second, pattern[125].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[126].first.second, pattern[126].first.first) < smoothedSum(sum, pt, pattern[126].second.second, pattern[126].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[127].first.second, pattern[127].first.first) < smoothedSum(sum, pt, pattern[127].second.second, pattern[127].second.first)) << 0);
    }