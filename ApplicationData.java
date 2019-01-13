package mobile.computing.ws1819;


public class ApplicationData {
	/*
	 * To indicate the type of data coming
	 * Type: string
	 */
	private String ApplicationData;
	
	/*
	 *To store encoded data
	 *Type: string 
	 */
	private String encoded;
	
	/*
	 * To set the ApplicationData attribute
	 * @param: string
	 * @return: void
	 */
	private void setApplicationData(String AD)
	{
		this.ApplicationData = AD;
	}
	
	/*
	 * To set the the Encoded attribute
	 * @param: string
	 * @return: void
	 */
	private void setencoded(String E)
	{
		this.encoded = E;
	}
	
	/*
	 * To get the ApplicationData attribute
	 * @param: 
	 * @return: string
	 */
	public String getApplicationData()
	{
		return ApplicationData;
	}
	
	/*
	 * To get the Encoded attribute
	 * @param: 
	 * @return: string
	 */
	public String getencoded()
	{
		return encoded;
	}
	
	/*
	 * To create a new object of the class ApplicationData
	 * @param: string, string
	 * @return: ApplicationData
	 */
	public static ApplicationData data(String AD,String E)
	{
		ApplicationData d = new ApplicationData();
		
		d.setApplicationData(AD);
		d.setencoded(E);
			return d;
	}
}
