#include <rbrief/rbrief.h>

#include <algorithm>
#include <vector>
#include <math.h>
#include <iostream>

using std::vector;

namespace cv {

RBriefDescriptorExtractor::RBriefDescriptorExtractor( int bytes ) :
		bytes_(bytes), test_fn_(NULL)
{
	switch (bytes)
	{
		case 4:
		{
			#include "matlab_data/initcode_4.i"
			test_fn_ = pixelTests4;
			break;
		}
		case 16:
		{
			#include "matlab_data/initcode_16.i"
			test_fn_ = pixelTests16;
			break;
		}
		case 32:
		{
			#include "matlab_data/initcode_32.i"
			test_fn_ = pixelTests32;
			break;
		}
		case 64:
		{
			#include "matlab_data/initcode_64.i"
			test_fn_ = pixelTests64;
			break;
		}
		default:
			CV_Error(CV_StsBadArg, "bytes must be 4, 16, 32, or 64");
	}

	patternRot = pattern;
}

bool RBriefDescriptorExtractor::setRotationCase( double rotation )
{
	bool changed = false;

	if( fabs( (rotation/M_PI) * 180.0 ) > 1.5 ) // apply dead-bend for rotation
	{
		changed = true;
		double cosAngle = cos(rotation);
		double sinAngle = sin(rotation);

		for( unsigned int i = 0; i < patternRot.size(); i++ )
		{
			patternRot[i].first.first = floor( ( cosAngle * pattern[i].first.first - sinAngle * pattern[i].first.second ) + 0.5 );
			patternRot[i].first.second = floor( ( sinAngle * pattern[i].first.first + cosAngle * pattern[i].first.second ) + 0.5 );
			patternRot[i].second.first = floor( ( cosAngle * pattern[i].second.first - sinAngle * pattern[i].second.second ) + 0.5 );
			patternRot[i].second.second = floor( ( sinAngle * pattern[i].second.first + cosAngle * pattern[i].second.second ) + 0.5 );
		}
	}

	return changed;
}

void RBriefDescriptorExtractor::freezeRotationCase()
{
	pattern = patternRot;
}

void RBriefDescriptorExtractor::computeImpl(const Mat& image, std::vector<KeyPoint>& keypoints, Mat& descriptors) const
{
	// Construct integral image for fast smoothing (box filter)
	Mat sum;
	integral(image, sum, CV_32S);

	//Remove keypoints very close to the border
	double border = sqrt(2)*PATCH_SIZE/2 + KERNEL_SIZE/2;
	int _border = ceil(border);
	removeBorderKeypoints(keypoints, image.size(), _border);

	descriptors = Mat::zeros(keypoints.size(), bytes_, CV_8U);
	test_fn_(sum, keypoints, descriptors, patternRot);
}

void RBriefDescriptorExtractor::pixelTests4(const Mat& sum, const std::vector<KeyPoint>& keypoints, Mat& descriptors, const std::vector< std::pair< std::pair<int,int>, std::pair<int,int> > > &pattern)
{
	#include "matlab_data/code_4.i"
}

void RBriefDescriptorExtractor::pixelTests16(const Mat& sum, const std::vector<KeyPoint>& keypoints, Mat& descriptors, const std::vector< std::pair< std::pair<int,int>, std::pair<int,int> > > &pattern)
{
	#include "matlab_data/code_16.i"
}

void RBriefDescriptorExtractor::pixelTests32(const Mat& sum, const std::vector<KeyPoint>& keypoints, Mat& descriptors, const std::vector< std::pair< std::pair<int,int>, std::pair<int,int> > > &pattern)
{
	#include "matlab_data/code_32.i"
}

void RBriefDescriptorExtractor::pixelTests64(const Mat& sum, const std::vector<KeyPoint>& keypoints, Mat& descriptors, const std::vector< std::pair< std::pair<int,int>, std::pair<int,int> > > &pattern)
{
	#include "matlab_data/code_64.i"
}

} // namespace cv
