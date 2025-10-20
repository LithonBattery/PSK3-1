#include "func.h"

void read(map<string, int>& m, int& sum, vector <string>& u, map<string, set<int>> &wocc)
{
	string link, temp;
	ifstream inurl("url.txt");
	stringstream urlbuff;
	urlbuff << inurl.rdbuf();
	link = R"(.*\.()"; 
	
	while (urlbuff >> temp)
	{
		link = link + temp + "|";
	}
	link.pop_back();
	link = link + ")$";
	
	map<string, int> a;
	ifstream in("data.txt");
	stringstream buff;
	buff << in.rdbuf();
	int ln = 1;
	string line;
	while (getline(buff, line))
	{
		stringstream sline(line);
		string word;
		while (sline >> word)
		{
			if (withURL(word, link))
			{
				if (endsWithSymbol(word, '.'))
				{
					word.pop_back();
				}
				if (endsWithSymbol(word, ','))
				{
					word.pop_back();
				}
				regex symbolsRegex("[?!@$%^()€$]");
				regex numbersRegex("[0-9]");
				bool cs = regex_search(word, symbolsRegex);
				bool cn = regex_search(word, numbersRegex);
				if (!cs && !cn)
				{
					u.push_back(word);
					m.erase(word);
				}
			}
			else
			{
				clean(word);
				a[word] = ln;
				wocc[word].insert(ln);
				m[word]++;
			}
		}
		ln++;
	}
	for (auto& i : m)
	{
		sum += i.second;
	}
	in.close();
}
void clean(string& word)
{
	word.erase(remove_if(word.begin(), word.end(), [&](unsigned char c) { return !isalpha(c); }), word.end());
	//cout << word << endl;
	//if (!isalpha(*word.begin()))
	//{
	//	word = word.substr(1);
	//}
	/*if (!isalpha(*word.end()))
	{
		word.pop_back();
	}*/
}
bool withURL(const string& text, const string& link)
{
	regex urlRegex(link);
	return regex_search(text, urlRegex);
}
bool endsWithSymbol(const string& str, char symbol)
{
	if (str.empty())
	{
		return false;
	}
	return str.back() == symbol;
}
void print( map<string, int>& m, int& sum, vector <string>& u, map<string, set<int>> &wocc)
{
	ofstream out("rez.txt");
	ostringstream buff;
	buff.clear();
	buff.str("");
	buff << "Repeating words      |  Times repeated  |  Rows" << endl;
	for (auto& i : m)
	{
		if (i.second > 1 && i.first != "")
		{
			buff << setw(21) << left << i.first << "|  " << setw(16) << left << i.second << "|  ";
			for (auto& k : wocc)
			{
				if (k.first == i.first)
				{
					for (auto& j : k.second)
					{
						buff << j << " ";
					}
				}
			}
			buff << endl;
		}
	}
	buff << endl << "Total word sum: " << sum << endl << endl;
	buff << "URL's: " << endl;
	for (auto& i : u)
	{
		buff << i << endl;
	}
	out << buff.str();
	out.close();
}